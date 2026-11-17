// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The volume on the host: the operations, the partition table, and the property the service exists
//! for: a cut of the power at every sector written leaves the last whole state.

use crate::fs::{Fs, Kind, Open, Storage, Whence};
use crate::gpt::{self, Class};
use crate::mem::{MemDevice, Survive};
use crate::{Device, Error, SECTOR};
use std::collections::BTreeMap;
use std::string::{String, ToString};
use std::vec::Vec;
use std::{format, vec};

const SECTORS: u64 = 4096;

fn storage() -> std::boxed::Box<Storage> {
    std::boxed::Box::new(Storage::new())
}

fn fresh() -> (MemDevice, std::boxed::Box<Storage>) {
    (MemDevice::new(SECTORS), storage())
}

#[test]
fn files_and_directories() {
    let (device, mut state) = fresh();
    let mut fs = Fs::new(device, &mut state).unwrap();
    assert_eq!(fs.mount(), Err(Error::Corrupt));
    fs.format().unwrap();
    fs.mount().unwrap();
    fs.mkdir(b"/d").unwrap();
    assert_eq!(fs.mkdir(b"/d"), Err(Error::Exists));
    let f = fs
        .open(b"/d/a", Open::READ_WRITE.with(Open::CREATE))
        .unwrap();
    assert_eq!(fs.write(f, b"hello world").unwrap(), 11);
    fs.sync(f).unwrap();
    assert_eq!(fs.seek(f, 6, Whence::Set).unwrap(), 6);
    let mut buf = [0u8; 16];
    let n = fs.read(f, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"world");
    assert_eq!(fs.size(f).unwrap(), 11);
    fs.truncate(f, 5).unwrap();
    assert_eq!(fs.size(f).unwrap(), 5);
    fs.close(f).unwrap();
    fs.rename(b"/d/a", b"/d/b").unwrap();
    assert_eq!(fs.stat(b"/d/a"), Err(Error::NoEntry));
    let info = fs.stat(b"/d/b").unwrap();
    assert_eq!((info.kind, info.size), (Kind::File, 5));
    assert_eq!(fs.stat(b"/d").unwrap().kind, Kind::Directory);
    assert_eq!(fs.remove(b"/d"), Err(Error::NotEmpty));
    let dir = fs.opendir(b"/d").unwrap();
    let mut names = Vec::new();
    while let Some(e) = fs.readdir(dir).unwrap() {
        names.push(String::from_utf8(e.name().to_vec()).unwrap());
    }
    fs.closedir(dir).unwrap();
    assert_eq!(names, [".", "..", "b"]);
    fs.remove(b"/d/b").unwrap();
    fs.remove(b"/d").unwrap();
    assert_eq!(
        fs.open(b"/nothing", Open::READ),
        Err(Error::NoEntry),
        "no such file"
    );
    fs.unmount().unwrap();
}

#[test]
fn every_slot_is_used_and_given_back() {
    let (device, mut state) = fresh();
    let mut fs = Fs::new(device, &mut state).unwrap();
    fs.format().unwrap();
    fs.mount().unwrap();
    let mut open = Vec::new();
    for i in 0..crate::FILES {
        open.push(
            fs.open(format!("/f{i}").as_bytes(), Open::WRITE.with(Open::CREATE))
                .unwrap(),
        );
    }
    assert_eq!(
        fs.open(b"/more", Open::WRITE.with(Open::CREATE)),
        Err(Error::NoMemory)
    );
    fs.close(open.pop().unwrap()).unwrap();
    let again = fs.open(b"/more", Open::WRITE.with(Open::CREATE)).unwrap();
    fs.close(again).unwrap();
    for f in open {
        fs.close(f).unwrap();
    }
}

#[test]
fn a_file_larger_than_a_block_round_trips() {
    let (device, mut state) = fresh();
    let mut fs = Fs::new(device, &mut state).unwrap();
    fs.format().unwrap();
    fs.mount().unwrap();
    let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7 + i / 251) as u8).collect();
    let f = fs
        .open(b"/big", Open::READ_WRITE.with(Open::CREATE))
        .unwrap();
    for chunk in data.chunks(10_000) {
        assert_eq!(fs.write(f, chunk).unwrap(), chunk.len());
    }
    fs.close(f).unwrap();
    fs.unmount().unwrap();
    let device = fs.into_device();
    let mut state = storage();
    let mut fs = Fs::new(device, &mut state).unwrap();
    fs.mount().unwrap();
    let f = fs.open(b"/big", Open::READ).unwrap();
    let mut back = vec![0u8; data.len() + 10];
    let mut have = 0;
    loop {
        let n = fs.read(f, &mut back[have..]).unwrap();
        if n == 0 {
            break;
        }
        have += n;
    }
    assert_eq!(&back[..have], &data[..]);
}

#[test]
fn the_volume_fills_and_says_no_space() {
    let (device, mut state) = fresh();
    let mut fs = Fs::new(device, &mut state).unwrap();
    fs.format().unwrap();
    fs.mount().unwrap();
    let f = fs.open(b"/fill", Open::WRITE.with(Open::CREATE)).unwrap();
    let chunk = [0xA5u8; 4096];
    let mut written = 0usize;
    let error = loop {
        match fs.write(f, &chunk) {
            Ok(n) => written += n,
            Err(e) => break e,
        }
        assert!(written < 4096 * 600, "the volume has 512 blocks");
    };
    assert_eq!(error, Error::NoSpace);
    fs.close(f).ok();
    // The file system still mounts and deleting makes room.
    fs.remove(b"/fill").unwrap();
    let g = fs.open(b"/small", Open::WRITE.with(Open::CREATE)).unwrap();
    fs.write(g, b"x").unwrap();
    fs.close(g).unwrap();
}

#[test]
fn the_window_keeps_inside() {
    let mut whole = MemDevice::new(100);
    let mut window = crate::Window {
        device: &mut whole,
        first: 10,
        sectors: 20,
    };
    let mut sector = [0u8; SECTOR];
    assert!(window.read(19, &mut sector).is_ok());
    assert!(window.read(20, &mut sector).is_err());
    assert!(window.write(20, &sector).is_err());
    assert!(window.write(u64::MAX, &sector).is_err());
}

// A table, its classes and a copy that heals.

#[test]
fn gpt_is_made_read_and_set() {
    let mut dev = MemDevice::new(131_072);
    assert_eq!(gpt::classify(&mut dev), Ok(Class::Blank));
    let layout = gpt::default_layout(dev.sectors()).unwrap();
    let table = gpt::create(&mut dev, &layout, 7).unwrap();
    assert_eq!(table.total, 2);
    let store = table.find(&gpt::TYPE_STORE).unwrap();
    let data = table.find(&gpt::TYPE_DATA).unwrap();
    assert_eq!(store.first, 2048);
    assert_eq!(store.sectors() % 2048, 0);
    assert_eq!(data.first, store.last + 1);
    assert!(data.last <= table.last_usable);
    let mut name = [0u8; 36];
    let len = data.name_ascii(&mut name);
    assert_eq!(&name[..len], b"data");
    assert_eq!(data.attributes & gpt::FORMATTED, 0);
    // The attribute is set in both copies.
    let after = gpt::set_attributes(&mut dev, data.index, gpt::FORMATTED).unwrap();
    assert_eq!(
        after.find(&gpt::TYPE_DATA).unwrap().attributes,
        gpt::FORMATTED
    );
    assert_eq!(after.find(&gpt::TYPE_STORE).unwrap().attributes, 0);
    // A damaged primary header reads from the backup.
    dev.write(1, &[0xFFu8; SECTOR]).unwrap();
    let healed = gpt::read(&mut dev).unwrap();
    assert!(healed.from_backup);
    assert_eq!(
        healed.find(&gpt::TYPE_DATA).unwrap().attributes,
        gpt::FORMATTED
    );
    // A volume with anything else on it is foreign.
    let mut other = MemDevice::new(131_072);
    other.write(5, &[1u8; SECTOR]).unwrap();
    assert!(matches!(
        gpt::classify(&mut other),
        Ok(Class::Foreign(found)) if found.sector == 5 && found.offset == 0
    ));
    assert!(gpt::default_layout(2048).is_none());
}

#[test]
fn foreign_says_where_the_first_byte_that_is_not_zero_is() {
    let mut dev = MemDevice::new(131_072);
    let mut sector = [0u8; SECTOR];
    for (i, b) in sector.iter_mut().enumerate().skip(300) {
        *b = (i % 251) as u8 + 1;
    }
    dev.write(7, &sector).unwrap();
    // A later sector with other bytes does not change the answer.
    dev.write(9, &[0xEEu8; SECTOR]).unwrap();
    let mut first = [0u8; 8];
    first.copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let mut last = [0u8; SECTOR];
    last[..8].copy_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
    dev.write(131_071, &last).unwrap();
    let mut one = [0u8; SECTOR];
    one[..8].copy_from_slice(&first);
    // Sector 1 holds bytes that are no header: the first non-zero byte is still in sector 1.
    dev.write(1, &one).unwrap();
    let Ok(Class::Foreign(found)) = gpt::classify(&mut dev) else {
        panic!("not foreign");
    };
    assert_eq!((found.sector, found.offset), (1, 0));
    assert_eq!(found.lba1, first);
    assert_eq!(found.last, [8, 7, 6, 5, 4, 3, 2, 1]);
    assert_eq!(&found.bytes[..8], &first);
    // Without sector 1 the byte in sector 7 is the first one, at offset 300.
    dev.write(1, &[0u8; SECTOR]).unwrap();
    // The backup header's sector is not zero either, so the sector 7 scan is the one that counts.
    let Ok(Class::Foreign(found)) = gpt::classify(&mut dev) else {
        panic!("not foreign");
    };
    assert_eq!((found.sector, found.offset), (7, 300));
    assert_eq!(found.lba1, [0; 8]);
    assert_eq!(found.bytes[..], sector[288..320]);
}

#[test]
fn blank_and_a_valid_table_have_no_foreign_report() {
    let mut dev = MemDevice::new(131_072);
    assert_eq!(gpt::classify(&mut dev), Ok(Class::Blank));
    let layout = gpt::default_layout(dev.sectors()).unwrap();
    gpt::create(&mut dev, &layout, 7).unwrap();
    assert!(matches!(gpt::classify(&mut dev), Ok(Class::Gpt(_))));
}

#[test]
fn a_table_whose_usable_sectors_cover_the_table_is_refused() {
    // Both copies say the usable sectors reach over the entries (the end ones, or the start ones),
    // with valid checksums.
    let patch = |dev: &mut MemDevice, lba: u64, at: usize, value: u64| {
        let mut sector = [0u8; SECTOR];
        dev.read(lba, &mut sector).unwrap();
        sector[at..at + 8].copy_from_slice(&value.to_le_bytes());
        sector[16..20].fill(0);
        let crc = gpt::crc32(0, &sector[..92]);
        sector[16..20].copy_from_slice(&crc.to_le_bytes());
        dev.write(lba, &sector).unwrap();
    };
    for (at, value) in [(48usize, 131_072 - 5), (40, 2)] {
        let mut dev = MemDevice::new(131_072);
        let layout = gpt::default_layout(dev.sectors()).unwrap();
        gpt::create(&mut dev, &layout, 7).unwrap();
        assert!(gpt::read(&mut dev).is_ok());
        patch(&mut dev, 1, at, value);
        patch(&mut dev, 131_071, at, value);
        assert_eq!(gpt::read(&mut dev), Err(gpt::Error::NoTable), "{at}");
    }
}

#[test]
fn gpt_has_the_standard_crc() {
    assert_eq!(gpt::crc32(0, b"123456789"), 0xCBF4_3926);
}

#[test]
fn a_cut_while_the_table_is_made_leaves_blank_or_a_table() {
    let layout = gpt::default_layout(131_072).unwrap();
    let mut total = 0;
    {
        let mut dev = MemDevice::new(131_072);
        gpt::create(&mut dev, &layout, 1).unwrap();
        total = dev.written.max(total);
    }
    for cut in 0..total {
        for survive in [Survive::None, Survive::All, Survive::Random(cut)] {
            let mut dev = MemDevice::new(131_072);
            dev.cut_after(Some(cut));
            let _ = gpt::create(&mut dev, &layout, 1);
            dev.power_cycle(survive);
            match gpt::classify(&mut dev).unwrap() {
                Class::Gpt(table) => {
                    assert_eq!(table.total, 2, "cut {cut}: a table is whole or not there");
                }
                Class::Blank => {}
                Class::Foreign(_) => panic!("cut {cut} {survive:?}: neither a table nor blank"),
            }
        }
    }
}

// The workload of the crash tests: a list of steps, each one call of the interface that is durable
// when it returns, so the state after a cut is the state of `done` steps or of `done + 1`.

#[derive(Clone, Debug, Eq, PartialEq)]
enum Node {
    Dir,
    File(Vec<u8>),
}

type Tree = BTreeMap<String, Node>;

#[derive(Clone, Debug)]
enum Step {
    Mkdir(&'static str),
    /// Create or replace the file with the contents, synced.
    Put(String, usize, u8),
    /// Append a record to the file, synced.
    Append(String, usize, u8),
    Rename(String, String),
    Remove(String),
}

fn pattern(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|i| {
            (i as u8)
                .wrapping_mul(31)
                .wrapping_add(salt)
                .wrapping_add((i >> 8) as u8)
        })
        .collect()
}

fn steps() -> Vec<Step> {
    let mut s = vec![Step::Mkdir("/d"), Step::Mkdir("/d/e")];
    for i in 0..6u8 {
        s.push(Step::Put(
            format!("/d/tmp{i}"),
            100 + usize::from(i) * 2900,
            i,
        ));
        s.push(Step::Rename(format!("/d/tmp{i}"), format!("/d/f{i}")));
    }
    for i in 0..5u8 {
        s.push(Step::Append(
            "/log".to_string(),
            180 + usize::from(i) * 70,
            i,
        ));
    }
    s.push(Step::Remove("/d/f1".to_string()));
    s.push(Step::Put("/d/f2".to_string(), 9000, 99));
    s.push(Step::Rename("/d/f3".to_string(), "/d/e/f3".to_string()));
    s.push(Step::Put("/d/f4".to_string(), 10, 5));
    s.push(Step::Remove("/d/f0".to_string()));
    s
}

fn apply(model: &mut Tree, step: &Step) {
    match step {
        Step::Mkdir(path) => {
            model.insert((*path).to_string(), Node::Dir);
        }
        Step::Put(path, len, salt) => {
            model.insert(path.clone(), Node::File(pattern(*len, *salt)));
        }
        Step::Append(path, len, salt) => {
            let Node::File(bytes) = model
                .entry(path.clone())
                .or_insert_with(|| Node::File(Vec::new()))
            else {
                unreachable!()
            };
            bytes.extend(pattern(*len, *salt));
        }
        Step::Rename(from, to) => {
            let node = model.remove(from).unwrap();
            model.insert(to.clone(), node);
        }
        Step::Remove(path) => {
            model.remove(path);
        }
    }
}

fn run<D: Device>(fs: &mut Fs<'_, D>, step: &Step) -> Result<(), Error> {
    match step {
        Step::Mkdir(path) => fs.mkdir(path.as_bytes()),
        Step::Put(path, len, salt) => {
            let f = fs.open(
                path.as_bytes(),
                Open::WRITE.with(Open::CREATE).with(Open::TRUNCATE),
            )?;
            let data = pattern(*len, *salt);
            let mut at = 0;
            while at < data.len() {
                at += fs.write(f, &data[at..(at + 1000).min(data.len())])?;
            }
            fs.sync(f)?;
            fs.close(f)
        }
        Step::Append(path, len, salt) => {
            let f = fs.open(
                path.as_bytes(),
                Open::WRITE.with(Open::CREATE).with(Open::APPEND),
            )?;
            fs.write(f, &pattern(*len, *salt))?;
            fs.sync(f)?;
            fs.close(f)
        }
        Step::Rename(from, to) => fs.rename(from.as_bytes(), to.as_bytes()),
        Step::Remove(path) => fs.remove(path.as_bytes()),
    }
}

fn read_tree<D: Device>(fs: &mut Fs<'_, D>) -> Result<Tree, Error> {
    fn walk<D: Device>(fs: &mut Fs<'_, D>, dir: &str, out: &mut Tree) -> Result<(), Error> {
        let d = fs.opendir(if dir.is_empty() { b"/" } else { dir.as_bytes() })?;
        let mut entries = Vec::new();
        while let Some(e) = fs.readdir(d)? {
            let name = String::from_utf8(e.name().to_vec()).unwrap();
            if name != "." && name != ".." {
                entries.push((name, e.kind));
            }
        }
        fs.closedir(d)?;
        for (name, kind) in entries {
            let path = format!("{dir}/{name}");
            match kind {
                Kind::Directory => {
                    out.insert(path.clone(), Node::Dir);
                    walk(fs, &path, out)?;
                }
                Kind::File => {
                    let f = fs.open(path.as_bytes(), Open::READ)?;
                    let mut bytes = Vec::new();
                    let mut buf = [0u8; 1500];
                    loop {
                        let n = fs.read(f, &mut buf)?;
                        if n == 0 {
                            break;
                        }
                        bytes.extend_from_slice(&buf[..n]);
                    }
                    fs.close(f)?;
                    out.insert(path, Node::File(bytes));
                }
            }
        }
        Ok(())
    }
    let mut out = Tree::new();
    walk(fs, "", &mut out)?;
    Ok(out)
}

/// One run: the steps on a fresh volume with a cut after `cut` sectors (None: no cut), then the
/// power returns with `survive`, the volume mounts and its tree is read. Returns the steps that
/// returned before the cut and the tree found.
fn crashed(cut: Option<u64>, survive: Survive, steps: &[Step]) -> (usize, Tree, u64) {
    let mut state = storage();
    let device = MemDevice::new(SECTORS);
    let mut fs = Fs::new(device, &mut state).unwrap();
    fs.format().unwrap();
    fs.mount().unwrap();
    fs.device().flush().unwrap();
    let before = fs.device().written;
    fs.device().cut_after(cut);
    let mut done = 0;
    for step in steps {
        if run(&mut fs, step).is_err() {
            break;
        }
        done += 1;
    }
    let written = fs.device().written - before;
    let mut device = fs.into_device();
    device.power_cycle(survive);
    let mut state = storage();
    let mut fs = Fs::new(device, &mut state).unwrap();
    fs.mount().expect("the volume mounts after the cut");
    let tree = read_tree(&mut fs).expect("the tree reads after the cut");
    (done, tree, written)
}

/// The state a step that creates a file passes through: littlefs makes the (empty) file when it is
/// opened and gives it its contents at the sync, so a cut between them leaves the file empty.
fn created_empty(before: &Tree, step: &Step) -> Option<Tree> {
    match step {
        Step::Put(path, ..) | Step::Append(path, ..) if !before.contains_key(path) => {
            let mut tree = before.clone();
            tree.insert(path.clone(), Node::File(Vec::new()));
            Some(tree)
        }
        _ => None,
    }
}

/// The tree as paths and lengths, for a message.
fn outline(tree: &Tree) -> Vec<String> {
    tree.iter()
        .map(|(path, node)| match node {
            Node::Dir => format!("{path}/"),
            Node::File(bytes) => format!("{path} {}", bytes.len()),
        })
        .collect()
}

fn models(steps: &[Step]) -> Vec<Tree> {
    let mut all = vec![Tree::new()];
    for step in steps {
        let mut next = all.last().unwrap().clone();
        apply(&mut next, step);
        all.push(next);
    }
    all
}

#[test]
fn the_steps_make_the_tree_the_model_says() {
    let steps = steps();
    let (done, tree, written) = crashed(None, Survive::All, &steps);
    assert_eq!(done, steps.len());
    assert_eq!(&tree, models(&steps).last().unwrap());
    assert!(written > 100, "the workload writes {written} sectors");
}

/// Every sector of the workload is a place the power can fail, and for each, every one of four
/// things the cache can do. The tree found is the state after the steps that returned, or after one
/// more: no step is half applied, and no file shows bytes of a write that was not synced.
#[test]
fn a_cut_at_every_sector_leaves_a_whole_state() {
    let steps = steps();
    let states = models(&steps);
    let (_, _, total) = crashed(None, Survive::All, &steps);
    let mut worst = 0;
    for cut in 0..total {
        for survive in [
            Survive::None,
            Survive::All,
            Survive::Random(cut * 2 + 1),
            Survive::Prefix(cut as usize % 5),
        ] {
            let (done, tree, _) = crashed(Some(cut), survive, &steps);
            let ok = tree == states[done]
                || tree == states[(done + 1).min(steps.len())]
                || done < steps.len()
                    && created_empty(&states[done], &steps[done]).is_some_and(|t| t == tree);
            assert!(
                ok,
                "cut {cut} {survive:?}: {done} steps returned (the next is {:?}), the tree is {:?}, the model after them {:?}",
                steps.get(done),
                outline(&tree),
                outline(&states[done])
            );
            worst = worst.max(done);
        }
    }
    assert_eq!(
        worst + 1,
        steps.len(),
        "the last cuts come after the last steps but one"
    );
}

/// What the cut leaves is a volume that goes on working: the file system takes the next writes.
#[test]
fn the_volume_after_a_cut_takes_writes() {
    let steps = steps();
    let (_, _, total) = crashed(None, Survive::All, &steps);
    for cut in (0..total).step_by(37) {
        let mut state = storage();
        let mut fs = Fs::new(MemDevice::new(SECTORS), &mut state).unwrap();
        fs.format().unwrap();
        fs.mount().unwrap();
        fs.device().flush().unwrap();
        fs.device().cut_after(Some(cut));
        for step in &steps {
            if run(&mut fs, step).is_err() {
                break;
            }
        }
        let mut device = fs.into_device();
        device.power_cycle(Survive::Random(cut));
        let mut state = storage();
        let mut fs = Fs::new(device, &mut state).unwrap();
        fs.mount().unwrap();
        run(&mut fs, &Step::Put("/after".to_string(), 5000, 3)).unwrap();
        let f = fs.open(b"/after", Open::READ).unwrap();
        let mut buf = vec![0u8; 6000];
        assert_eq!(fs.read(f, &mut buf).unwrap(), 5000);
        assert_eq!(&buf[..5000], &pattern(5000, 3)[..]);
    }
}

/// A write that is not synced shows nothing after a cut: the file has the contents of its last sync
/// (empty for a file the open made).
#[test]
fn an_unsynced_write_is_lost_whole() {
    let mut state = storage();
    let mut fs = Fs::new(MemDevice::new(SECTORS), &mut state).unwrap();
    fs.format().unwrap();
    fs.mount().unwrap();
    run(&mut fs, &Step::Put("/keep".to_string(), 3000, 1)).unwrap();
    let f = fs.open(b"/keep", Open::WRITE.with(Open::TRUNCATE)).unwrap();
    fs.write(f, &pattern(20_000, 9)).unwrap();
    let g = fs.open(b"/new", Open::WRITE.with(Open::CREATE)).unwrap();
    fs.write(g, &pattern(10, 9)).unwrap();
    // No sync, no close: the power goes.
    let mut device = fs.into_device();
    device.power_cycle(Survive::All);
    let mut state = storage();
    let mut fs = Fs::new(device, &mut state).unwrap();
    fs.mount().unwrap();
    let tree = read_tree(&mut fs).unwrap();
    assert_eq!(tree.get("/keep"), Some(&Node::File(pattern(3000, 1))));
    // The file made by the open is there and empty: nothing of the unsynced write.
    assert_eq!(tree.get("/new"), Some(&Node::File(Vec::new())));
}

mod served {
    use super::*;
    use crate::server::Server;
    use proto_data as p;
    use proto_wire::{Reader, Status, Writer};

    struct Rig {
        server: Server,
        state: std::boxed::Box<Storage>,
    }

    fn call(
        server: &mut Server,
        fs: &mut Fs<'_, MemDevice>,
        owner: u64,
        build: impl FnOnce(&mut Writer) -> Result<(), Status>,
    ) -> Result<Vec<u8>, Status> {
        let mut w = Writer::new();
        build(&mut w).unwrap();
        let reply = server.handle(fs, owner, w.as_bytes());
        p::reply(reply.as_bytes()).map(|mut r| r.bytes(r.left()).unwrap().to_vec())
    }

    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn a_session_works_through_the_protocol() {
        let mut rig = Rig {
            server: Server::new(),
            state: storage(),
        };
        let mut fs = Fs::new(MemDevice::new(SECTORS), &mut rig.state).unwrap();
        // Not mounted yet.
        assert_eq!(
            call(&mut rig.server, &mut fs, 1, p::statfs),
            Err(p::code(p::NOT_READY))
        );
        fs.format().unwrap();
        fs.mount().unwrap();
        let s = &mut rig.server;
        call(s, &mut fs, 1, |w| {
            p::path_call(p::Method::Mkdir, b"/ssh", w)
        })
        .unwrap();
        let opened = call(s, &mut fs, 1, |w| {
            p::open(b"//ssh/./key", p::WRITE | p::READ | p::CREATE, w)
        })
        .unwrap();
        let handle = word(&opened, 0);
        assert_eq!(word(&opened, 4), p::KIND_FILE);
        call(s, &mut fs, 1, |w| p::write(handle, b"secret", w)).unwrap();
        call(s, &mut fs, 1, |w| {
            p::handle_call(p::Method::Fsync, handle, w)
        })
        .unwrap();
        // Another session cannot use the handle; the file in use cannot go.
        assert_eq!(
            call(s, &mut fs, 2, |w| p::read(handle, 10, w)),
            Err(p::code(p::BAD_HANDLE))
        );
        assert_eq!(
            call(s, &mut fs, 2, |w| p::path_call(
                p::Method::Unlink,
                b"/ssh/key",
                w
            )),
            Err(p::code(p::BUSY))
        );
        assert_eq!(
            call(s, &mut fs, 2, |w| p::rename(b"/ssh", b"/other", w)),
            Err(p::code(p::BUSY))
        );
        call(s, &mut fs, 1, |w| p::seek(handle, 0, p::SEEK_SET, w)).unwrap();
        let read = call(s, &mut fs, 1, |w| p::read(handle, 100, w)).unwrap();
        assert_eq!((word(&read, 0), &read[4..]), (6, &b"secret"[..]));
        let stat = call(s, &mut fs, 2, |w| {
            p::path_call(p::Method::Stat, b"/ssh/key", w)
        })
        .unwrap();
        assert_eq!((word(&stat, 0), word(&stat, 4)), (p::KIND_FILE, 6));
        // The session goes: its files close, and the file can be renamed.
        s.gone(&mut fs, 1);
        assert_eq!(s.open_count(), 0);
        assert_eq!(
            call(s, &mut fs, 1, |w| p::read(handle, 10, w)),
            Err(p::code(p::BAD_HANDLE))
        );
        call(s, &mut fs, 2, |w| p::rename(b"/ssh/key", b"/ssh/key2", w)).unwrap();
        // A directory, listed.
        let dir = word(
            &call(s, &mut fs, 2, |w| p::open(b"/ssh", p::DIRECTORY, w)).unwrap(),
            0,
        );
        let mut names = Vec::new();
        loop {
            let e = call(s, &mut fs, 2, |w| {
                p::handle_call(p::Method::Readdir, dir, w)
            })
            .unwrap();
            if word(&e, 0) == 0 {
                break;
            }
            names.push(String::from_utf8(e[12..].to_vec()).unwrap());
        }
        assert_eq!(names, [".", "..", "key2"]);
        assert_eq!(
            call(s, &mut fs, 2, |w| p::path_call(
                p::Method::Rmdir,
                b"/ssh",
                w
            )),
            Err(p::code(p::BUSY))
        );
        call(s, &mut fs, 2, |w| p::handle_call(p::Method::Close, dir, w)).unwrap();
        assert_eq!(
            call(s, &mut fs, 2, |w| p::path_call(
                p::Method::Rmdir,
                b"/ssh",
                w
            )),
            Err(p::code(p::NOT_EMPTY))
        );
        assert_eq!(
            call(s, &mut fs, 2, |w| p::path_call(
                p::Method::Stat,
                b"/ssh/../x",
                w
            )),
            Err(p::code(p::INVALID))
        );
        let space = call(s, &mut fs, 2, p::statfs).unwrap();
        assert_eq!(word(&space, 0), (SECTORS / 8) as u32);
        let _ = Reader::new(&[]);
    }
}

mod volumes {
    use super::*;
    use crate::volume::{self, Did, Refusal};

    #[test]
    fn a_blank_disk_is_partitioned_formatted_and_then_only_mounted() {
        let mut state = storage();
        let (mut fs, did, part) = volume::open(MemDevice::new(131_072), &mut state, 5).unwrap();
        assert_eq!(did, Did::Partitioned);
        let f = fs.open(b"/x", Open::WRITE.with(Open::CREATE)).unwrap();
        fs.write(f, b"kept").unwrap();
        fs.sync(f).unwrap();
        fs.close(f).unwrap();
        let mut disk = fs.into_device().device;
        disk.power_cycle(Survive::None);
        let mut state = storage();
        let (mut fs, did, again) = volume::open(disk, &mut state, 6).unwrap();
        assert_eq!(did, Did::Mounted);
        assert_eq!(part.first, again.first);
        assert_eq!(fs.stat(b"/x").unwrap().size, 4);
        // The store partition before it is untouched: zeros.
        let store = gpt::read(&mut fs.device().device)
            .unwrap()
            .find(&gpt::TYPE_STORE)
            .unwrap();
        let mut sector = [0xFFu8; SECTOR];
        fs.device().device.read(store.first, &mut sector).unwrap();
        assert!(sector.iter().all(|&b| b == 0));
    }

    #[test]
    fn what_is_not_ours_is_left_alone() {
        // A disk with a boot sector.
        let mut disk = MemDevice::new(131_072);
        disk.write(0, &[0x55u8; SECTOR]).unwrap();
        disk.flush().unwrap();
        let before = disk.medium().to_vec();
        let mut state = storage();
        assert!(matches!(
            volume::open(&mut disk, &mut state, 1).err(),
            Some(Refusal::Foreign(found)) if found.sector == 0 && found.bytes[..4] == [0x55; 4]
        ));
        assert_eq!(disk.medium(), &before[..]);
        // A table with no data partition.
        let mut disk = MemDevice::new(131_072);
        let only_store = [gpt::New {
            kind: gpt::TYPE_STORE,
            first: 2048,
            last: 4095,
            name: "store",
        }];
        gpt::create(&mut disk, &only_store, 3).unwrap();
        let before = disk.medium().to_vec();
        let mut state = storage();
        assert_eq!(
            volume::open(&mut disk, &mut state, 1).err(),
            Some(Refusal::NoPartition)
        );
        assert_eq!(disk.medium(), &before[..]);
    }

    #[test]
    fn a_formatted_partition_that_does_not_mount_is_not_formatted_again() {
        let mut state = storage();
        let (fs, _, part) = volume::open(MemDevice::new(131_072), &mut state, 5).unwrap();
        let mut disk = fs.into_device().device;
        disk.write(part.first, &[0u8; SECTOR * 16]).unwrap();
        disk.flush().unwrap();
        let before = disk.medium().to_vec();
        let mut state = storage();
        assert_eq!(
            volume::open(&mut disk, &mut state, 1).err(),
            Some(Refusal::Damaged)
        );
        assert_eq!(disk.medium(), &before[..]);
    }

    /// Opens the volume on boot `seed`; on the first call after a cut writes a file, later calls
    /// read it back.
    fn boot(disk: &mut MemDevice, seed: u64, write: bool) -> Result<volume::Did, String> {
        let mut state = storage();
        let (mut fs, did, part) = volume::open(&mut *disk, &mut state, seed)
            .map_err(|e| format!("boot {seed}: {e:?}"))?;
        if part.kind != gpt::TYPE_DATA {
            return Err(format!("boot {seed}: another partition"));
        }
        if write {
            let f = fs.open(b"/boot", Open::WRITE.with(Open::CREATE)).unwrap();
            fs.write(f, b"second boot").unwrap();
            fs.sync(f).unwrap();
            fs.close(f).unwrap();
        } else {
            let f = fs
                .open(b"/boot", Open::READ)
                .map_err(|e| format!("boot {seed}: {e:?}"))?;
            let mut out = [0u8; 16];
            let n = fs.read(f, &mut out).unwrap();
            fs.close(f).unwrap();
            if &out[..n] != b"second boot" {
                return Err(format!("boot {seed}: the data differs"));
            }
        }
        fs.unmount().unwrap();
        Ok(did)
    }

    fn three_boots(disk: &mut MemDevice) -> Result<(), String> {
        boot(disk, 2, true)?;
        boot(disk, 3, false)?;
        boot(disk, 4, false)?;
        Ok(())
    }

    #[test]
    fn a_cut_in_the_first_use_leaves_a_disk_that_opens() {
        let (_, _, total) = {
            let mut state = storage();
            let mut disk = MemDevice::new(131_072);
            let (fs, ..) = volume::open(&mut disk, &mut state, 1).unwrap();
            let _ = fs;
            (0, 0, disk.written)
        };
        for cut in 0..total {
            for survive in [
                Survive::None,
                Survive::All,
                Survive::Random(cut),
                Survive::Prefix(1),
            ] {
                let mut disk = MemDevice::new(131_072);
                disk.cut_after(Some(cut));
                {
                    let mut state = storage();
                    let _ = volume::open(&mut disk, &mut state, 1);
                }
                disk.power_cycle(survive);
                let result = three_boots(&mut disk);
                assert!(result.is_ok(), "cut {cut} {survive:?}: {result:?}");
            }
        }
    }

    /// A cut at every sector of `set_attributes` itself, in every way the cache can survive.
    #[test]
    fn a_cut_in_set_attributes_leaves_a_disk_that_opens() {
        // A formatted volume whose attribute is cleared, so that either answer of the sweep opens.
        let mut disk = MemDevice::new(131_072);
        let part = {
            let mut state = storage();
            let (_, _, part) = volume::open(&mut disk, &mut state, 1).unwrap();
            part
        };
        gpt::set_attributes(&mut disk, part.index, 0).unwrap();
        let base = disk.written;
        let mut whole = disk.clone();
        gpt::set_attributes(&mut whole, part.index, gpt::FORMATTED).unwrap();
        let writes = whole.written - base;
        assert!(writes >= 35, "{writes}");
        for cut in 0..=writes {
            for survive in [
                Survive::None,
                Survive::All,
                Survive::Random(cut),
                Survive::Prefix(1),
            ] {
                let mut d = disk.clone();
                d.cut_after(Some(cut));
                let _ = gpt::set_attributes(&mut d, part.index, gpt::FORMATTED);
                d.power_cycle(survive);
                let result = three_boots(&mut d);
                assert!(result.is_ok(), "cut {cut} {survive:?}: {result:?}");
            }
        }
    }
}
