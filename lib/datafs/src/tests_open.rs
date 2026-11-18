// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! How littlefs 2.11 behaves with a file that is open while the name goes or the file is written
//! through another open of the same name.

use crate::fs::{Fs, Open, Storage, Whence};
use crate::mem::MemDevice;
use std::vec::Vec;

fn mounted(state: &mut Storage) -> Fs<'_, MemDevice> {
    let mut fs = Fs::new(MemDevice::new(4096), state).unwrap();
    fs.format().unwrap();
    fs.mount().unwrap();
    fs
}

fn bytes(len: usize, salt: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(7) ^ salt).collect()
}

fn read_all(fs: &mut Fs<'_, MemDevice>, f: crate::fs::File) -> Result<Vec<u8>, crate::Error> {
    fs.seek(f, 0, Whence::Set)?;
    let mut out = Vec::new();
    let mut buf = [0u8; 1000];
    loop {
        let n = fs.read(f, &mut buf)?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buf[..n]);
    }
}

fn churn(fs: &mut Fs<'_, MemDevice>) {
    // Writes and removes enough to take every block of the disk more than once.
    for i in 0..300 {
        let g = fs.open(b"/g", Open::WRITE.with(Open::CREATE)).unwrap();
        fs.write(g, &bytes(20000, i as u8)).unwrap();
        fs.close(g).unwrap();
        fs.remove(b"/g").unwrap();
    }
}

fn written(fs: &mut Fs<'_, MemDevice>, name: &[u8], data: &[u8]) -> crate::fs::File {
    let f = fs.open(name, Open::READ_WRITE.with(Open::CREATE)).unwrap();
    fs.write(f, data).unwrap();
    fs.sync(f).unwrap();
    f
}

/// What littlefs does, recorded: a file that is open when its name is removed keeps its contents
/// only while they are inline in the directory (up to a few hundred bytes). A larger one reads
/// garbage or CORRUPT once the volume reuses its blocks, so the service must not rely on it.
#[test]
fn littlefs_loses_the_blocks_of_an_unlinked_open_file() {
    for (len, kept) in [(10usize, true), (300, true), (5000, false), (40000, false)] {
        let mut state = Storage::new();
        let mut fs = mounted(&mut state);
        let data = bytes(len, 1);
        let f = written(&mut fs, b"/a", &data);
        fs.remove(b"/a").unwrap();
        assert_eq!(
            read_all(&mut fs, f).as_ref(),
            Ok(&data),
            "right after, {len}"
        );
        churn(&mut fs);
        assert_eq!(
            read_all(&mut fs, f).as_ref() == Ok(&data),
            kept,
            "after, {len}"
        );
        let _ = fs.close(f);
    }
}

/// A file replaced by a rename is in the same case.
#[test]
fn littlefs_loses_the_blocks_of_an_open_file_that_a_rename_replaces() {
    let mut state = Storage::new();
    let mut fs = mounted(&mut state);
    let data = bytes(40000, 1);
    let f = written(&mut fs, b"/a", &data);
    let h = written(&mut fs, b"/b", b"small");
    fs.close(h).unwrap();
    fs.rename(b"/b", b"/a").unwrap();
    churn(&mut fs);
    assert_ne!(read_all(&mut fs, f).as_ref(), Ok(&data));
    assert_eq!(fs.stat(b"/a").unwrap().size, 5);
    let _ = fs.close(f);
}

/// A rename of an open file detaches it from its name too: a write through the open file after the
/// rename is not committed by the sync, which still returns success.
#[test]
fn littlefs_detaches_an_open_file_that_is_renamed() {
    let mut state = Storage::new();
    let mut fs = mounted(&mut state);
    let data = bytes(40000, 1);
    let f = written(&mut fs, b"/c", &data);
    fs.rename(b"/c", b"/d").unwrap();
    assert_eq!(fs.write(f, b"tail").unwrap(), 4);
    fs.sync(f).unwrap();
    fs.close(f).unwrap();
    assert_eq!(fs.stat(b"/d").unwrap().size, 40000, "the tail is lost");
}

/// Two opens of one name do not see each other: the second shows the size and the blocks it had at
/// its open, and the last sync overwrites the entry. Neither two writers nor two appenders keep each
/// other's bytes, which is why the service shares one open file among the descriptions of a path.
#[test]
fn littlefs_gives_two_opens_of_one_name_no_common_view() {
    let mut state = Storage::new();
    let mut fs = mounted(&mut state);
    let one = fs.open(b"/t", Open::READ_WRITE.with(Open::CREATE)).unwrap();
    let two = fs.open(b"/t", Open::READ_WRITE).unwrap();
    fs.write(one, &bytes(5000, 3)).unwrap();
    fs.sync(one).unwrap();
    assert_eq!(fs.size(one).unwrap(), 5000);
    assert_eq!(fs.size(two).unwrap(), 0);
    fs.write(two, b"ZZZZ").unwrap();
    fs.sync(two).unwrap();
    assert_eq!(
        fs.stat(b"/t").unwrap().size,
        4,
        "the first writer's bytes are gone"
    );
    fs.close(one).unwrap();
    fs.close(two).unwrap();
    let a1 = fs
        .open(b"/p", Open::WRITE.with(Open::CREATE).with(Open::APPEND))
        .unwrap();
    let a2 = fs.open(b"/p", Open::WRITE.with(Open::APPEND)).unwrap();
    fs.write(a1, b"AAAA").unwrap();
    fs.sync(a1).unwrap();
    fs.write(a2, b"BBBB").unwrap();
    fs.sync(a2).unwrap();
    fs.close(a1).unwrap();
    fs.close(a2).unwrap();
    let r = fs.open(b"/p", Open::READ).unwrap();
    assert_eq!(read_all(&mut fs, r).unwrap(), b"BBBB");
}

/// The same through the protocol: descriptions, sessions, clones and passes.
mod served {
    use super::*;
    use crate::mem::Survive;
    use crate::server::{self, Server};
    use crate::{Device, Error};
    use proto_data as p;
    use proto_wire::{Status, Writer};
    use std::string::String;

    type Res = Result<Vec<u8>, Status>;

    struct Rig<'a> {
        server: Server,
        fs: Fs<'a, MemDevice>,
    }

    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    impl<'a> Rig<'a> {
        fn new(state: &'a mut Storage) -> Rig<'a> {
            Rig {
                server: Server::with_epoch(7),
                fs: mounted(state),
            }
        }

        fn call(
            &mut self,
            owner: u64,
            aux: u64,
            build: impl FnOnce(&mut Writer) -> Result<(), Status>,
        ) -> Res {
            let mut w = Writer::new();
            build(&mut w).unwrap();
            let reply = self.server.handle(&mut self.fs, owner, aux, w.as_bytes());
            p::reply(reply.as_bytes()).map(|mut r| r.bytes(r.left()).unwrap().to_vec())
        }

        fn open(&mut self, owner: u64, path: &[u8], flags: u32) -> u32 {
            word(&self.try_open(owner, path, flags).unwrap(), 0)
        }

        fn try_open(&mut self, owner: u64, path: &[u8], flags: u32) -> Res {
            self.call(owner, 0, |w| p::open(path, flags, w))
        }

        fn write(&mut self, owner: u64, h: u32, data: &[u8]) -> u32 {
            word(&self.call(owner, 0, |w| p::write(h, data, w)).unwrap(), 0)
        }

        /// All of `data` through WRITE, in messages.
        fn fill(&mut self, owner: u64, h: u32, data: &[u8]) {
            for chunk in data.chunks(900) {
                assert_eq!(self.write(owner, h, chunk) as usize, chunk.len());
            }
        }

        /// The whole file through PREAD, in messages.
        fn pread_all(&mut self, owner: u64, h: u32) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let more = self.pread(owner, h, 900, out.len() as u64);
                if more.is_empty() {
                    return out;
                }
                out.extend_from_slice(&more);
            }
        }

        fn read(&mut self, owner: u64, h: u32, count: u32) -> Vec<u8> {
            let r = self.call(owner, 0, |w| p::read(h, count, w)).unwrap();
            r[4..].to_vec()
        }

        fn pread(&mut self, owner: u64, h: u32, count: u32, at: u64) -> Vec<u8> {
            let r = self.call(owner, 0, |w| p::pread(h, count, at, w)).unwrap();
            r[4..].to_vec()
        }

        fn close(&mut self, owner: u64, h: u32) -> Res {
            self.call(owner, 0, |w| p::handle_call(p::Method::Close, h, w))
        }

        fn seek(&mut self, owner: u64, h: u32, at: i64, whence: u32) -> Res {
            self.call(owner, 0, |w| p::seek(h, at, whence, w))
        }

        fn path(&mut self, owner: u64, method: p::Method, path: &[u8]) -> Res {
            self.call(owner, 0, |w| p::path_call(method, path, w))
        }

        fn list(&mut self, owner: u64, path: &[u8]) -> Vec<String> {
            let dir = self.open(owner, path, p::DIRECTORY);
            let mut names = Vec::new();
            loop {
                let e = self
                    .call(owner, 0, |w| p::handle_call(p::Method::Readdir, dir, w))
                    .unwrap();
                if word(&e, 0) == 0 {
                    break;
                }
                names.push(String::from_utf8(e[12..].to_vec()).unwrap());
            }
            self.close(owner, dir).unwrap();
            names
        }
    }

    const RW: u32 = p::READ | p::WRITE | p::CREATE;

    #[test]
    fn each_description_has_its_position_and_the_file_is_shared() {
        let mut state = Storage::new();
        let mut t = Rig::new(&mut state);
        let a = t.open(1, b"/f", RW);
        let b = t.open(1, b"/f", p::READ);
        assert_eq!(t.server.node_count(), 1);
        assert_eq!(t.write(1, a, b"hello world"), 11);
        // The second description starts at 0 whatever the first did, and sees the unsynced write.
        assert_eq!(t.read(1, b, 5), b"hello");
        assert_eq!(t.read(1, b, 100), b" world");
        assert_eq!(t.read(1, b, 100), b"");
        assert_eq!(t.read(1, a, 100), b"");
        assert_eq!(word(&t.seek(1, a, 6, p::SEEK_SET).unwrap(), 0), 6);
        assert_eq!(t.read(1, a, 3), b"wor");
        assert_eq!(word(&t.seek(1, a, -2, p::SEEK_CUR).unwrap(), 0), 7);
        assert_eq!(word(&t.seek(1, a, -1, p::SEEK_END).unwrap(), 0), 10);
        assert_eq!(
            t.seek(1, a, -50, p::SEEK_CUR),
            Err(p::code(p::INVALID)),
            "before the start"
        );
        // A write through the read-only one is refused; the read through a write-only too.
        assert_eq!(
            t.call(1, 0, |w| p::write(b, b"x", w)),
            Err(p::code(p::BAD_HANDLE))
        );
        let c = t.open(1, b"/f", p::WRITE);
        assert_eq!(
            t.call(1, 0, |w| p::read(c, 1, w)),
            Err(p::code(p::BAD_HANDLE))
        );
        // The file closes with the last description.
        for h in [a, b, c] {
            t.close(1, h).unwrap();
        }
        assert_eq!((t.server.node_count(), t.server.open_count()), (0, 0));
        assert_eq!(t.fs.stat(b"/f").unwrap().size, 11);
    }

    #[test]
    fn pread_and_pwrite_leave_the_position_alone() {
        let mut state = Storage::new();
        let mut t = Rig::new(&mut state);
        let f = t.open(1, b"/f", RW);
        t.write(1, f, b"0123456789");
        t.seek(1, f, 2, p::SEEK_SET).unwrap();
        assert_eq!(t.pread(1, f, 4, 5), b"5678");
        assert_eq!(
            word(&t.call(1, 0, |w| p::pwrite(f, 8, b"AB", w)).unwrap(), 0),
            2
        );
        assert_eq!(t.read(1, f, 3), b"234", "the position is still 2");
        assert_eq!(t.pread(1, f, 20, 0), b"01234567AB");
        // Past the end: the gap reads as zeros.
        t.call(1, 0, |w| p::pwrite(f, 20, b"Z", w)).unwrap();
        let all = t.pread(1, f, 100, 0);
        assert_eq!(all.len(), 21);
        assert_eq!(&all[10..20], &[0u8; 10]);
        assert_eq!(
            t.call(1, 0, |w| p::pread(f, 1, 1 << 40, w)),
            Err(p::code(p::TOO_BIG))
        );
        t.close(1, f).unwrap();
    }

    #[test]
    fn append_writes_go_to_the_end_whoever_wrote_last() {
        let mut state = Storage::new();
        let mut t = Rig::new(&mut state);
        let a = t.open(1, b"/log", p::WRITE | p::CREATE | p::APPEND);
        let b = t.open(2, b"/log", p::WRITE | p::READ | p::APPEND);
        for i in 0..5u8 {
            t.write(1, a, &[b'a' + i; 3]);
            t.write(2, b, &[b'A' + i; 3]);
        }
        let r = t.open(3, b"/log", p::READ);
        assert_eq!(t.read(3, r, 100), b"aaaAAAbbbBBBcccCCCdddDDDeeeEEE");
        // The position after an append write is the end of that write; PWRITE appends too.
        assert_eq!(word(&t.seek(1, a, 0, p::SEEK_CUR).unwrap(), 0), 27);
        t.write(1, a, b"zz");
        assert_eq!(word(&t.seek(1, a, 0, p::SEEK_CUR).unwrap(), 0), 32);
        t.call(1, 0, |w| p::pwrite(a, 0, b"!", w)).unwrap();
        assert_eq!(t.pread(3, r, 100, 28), b"EEzz!");
        // The flag is the description's: GET_FLAGS shows it, SET_FLAGS turns it off for one.
        let flags = t
            .call(1, 0, |w| p::handle_call(p::Method::GetFlags, a, w))
            .unwrap();
        assert_eq!(word(&flags, 0), p::WRITE | p::APPEND);
        t.call(1, 0, |w| p::set_flags(a, 0, w)).unwrap();
        t.call(1, 0, |w| p::pwrite(a, 0, b"X", w)).unwrap();
        assert_eq!(t.pread(3, r, 2, 0), b"Xa");
        assert_eq!(
            t.call(1, 0, |w| p::set_flags(a, p::WRITE, w)),
            Err(p::code(p::INVALID))
        );
    }

    #[test]
    fn an_unlinked_open_file_stays_until_its_last_description_closes() {
        let mut state = Storage::new();
        let mut t = Rig::new(&mut state);
        let data = bytes(40000, 9);
        let f = t.open(1, b"/big", RW);
        t.fill(1, f, &data);
        t.call(1, 0, |w| p::handle_call(p::Method::Fsync, f, w))
            .unwrap();
        let g = t.open(2, b"/big", p::READ);
        let used = t.fs.used_blocks().unwrap();
        t.path(2, p::Method::Unlink, b"/big").unwrap();
        assert_eq!(
            t.path(2, p::Method::Stat, b"/big"),
            Err(p::code(p::NO_ENTRY))
        );
        // Another file by the same name is another file.
        let n = t.open(3, b"/big", RW);
        t.write(3, n, b"new");
        // The orphan is hidden from every way in.
        assert_eq!(t.list(3, b"/"), [".", "..", "big"]);
        for method in [p::Method::Stat, p::Method::Mkdir, p::Method::Unlink] {
            assert_eq!(
                t.path(3, method, b"/.orphans"),
                Err(p::code(p::NO_ENTRY)),
                "{method:?}"
            );
        }
        assert_eq!(
            t.try_open(3, b"/.orphans/1", p::READ),
            Err(p::code(p::NO_ENTRY))
        );
        assert_eq!(
            t.call(3, 0, |w| p::rename(b"/big", b"/.orphans/9", w)),
            Err(p::code(p::NO_ENTRY))
        );
        churn(&mut t.fs);
        // Both descriptions still read the old file whole, and the one that writes still can.
        assert_eq!(t.pread_all(2, g), data);
        t.seek(1, f, 0, p::SEEK_END).unwrap();
        t.write(1, f, b"tail");
        assert_eq!(t.pread(2, g, 4, 40000), b"tail");
        t.close(1, f).unwrap();
        assert_eq!(t.pread(2, g, 4, 0), data[..4]);
        assert!(t.fs.used_blocks().unwrap() >= used);
        t.close(2, g).unwrap();
        // The last close removed it: nothing under the orphans, the blocks are back.
        assert_eq!(server::clean_orphans(&mut t.fs), Ok(0));
        assert!(t.fs.used_blocks().unwrap() < used);
        t.close(3, n).unwrap();
        assert_eq!(t.server.node_count(), 0);
    }

    #[test]
    fn an_open_file_can_be_renamed_and_written_after() {
        let mut state = Storage::new();
        let mut t = Rig::new(&mut state);
        let data = bytes(40000, 5);
        let f = t.open(1, b"/c", RW);
        t.fill(1, f, &data);
        let r = t.open(2, b"/c", p::READ);
        t.call(1, 0, |w| p::rename(b"/c", b"/d", w)).unwrap();
        assert_eq!(t.path(1, p::Method::Stat, b"/c"), Err(p::code(p::NO_ENTRY)));
        // The position of each description is where it was; a write after the rename is kept.
        assert_eq!(t.write(1, f, b"tail"), 4);
        t.call(1, 0, |w| p::handle_call(p::Method::Fsync, f, w))
            .unwrap();
        assert_eq!(t.fs.stat(b"/d").unwrap().size, 40004);
        assert_eq!(t.pread(2, r, 4, 40000), b"tail");
        // A new open of the new name shares the file.
        let again = t.open(3, b"/d", p::READ);
        assert_eq!(t.server.node_count(), 1);
        assert_eq!(t.read(3, again, 3), data[..3]);
        for (o, h) in [(1, f), (2, r), (3, again)] {
            t.close(o, h).unwrap();
        }
    }

    #[test]
    fn a_rename_over_an_open_file_leaves_the_old_one_to_its_readers() {
        let mut state = Storage::new();
        let mut t = Rig::new(&mut state);
        let old = bytes(30000, 1);
        let f = t.open(1, b"/target", RW);
        t.fill(1, f, &old);
        let src = t.open(2, b"/src", RW);
        t.write(2, src, b"replacement");
        t.close(2, src).unwrap();
        t.call(2, 0, |w| p::rename(b"/src", b"/target", w)).unwrap();
        churn(&mut t.fs);
        assert_eq!(t.pread_all(1, f), old);
        let now = t.open(2, b"/target", p::READ);
        assert_eq!(t.read(2, now, 100), b"replacement");
        t.close(2, now).unwrap();
        t.close(1, f).unwrap();
        assert_eq!(t.list(2, b"/"), [".", "..", "target"]);
        assert_eq!(server::clean_orphans(&mut t.fs), Ok(0));
    }

    #[test]
    fn what_a_cut_leaves_under_the_orphans_goes_at_the_next_mount() {
        let mut state = Storage::new();
        let mut t = Rig::new(&mut state);
        let before = t.fs.used_blocks().unwrap();
        let f = t.open(1, b"/big", RW);
        t.fill(1, f, &bytes(60000, 2));
        t.call(1, 0, |w| p::handle_call(p::Method::Fsync, f, w))
            .unwrap();
        t.path(1, p::Method::Unlink, b"/big").unwrap();
        // The power goes with the file open: nothing closed it.
        t.fs.device().flush().unwrap();
        let mut device = core::mem::replace(t.fs.device(), MemDevice::new(16));
        device.power_cycle(Survive::None);
        let mut state2 = Storage::new();
        let mut fs = Fs::new(device, &mut state2).unwrap();
        fs.mount().unwrap();
        assert!(
            fs.used_blocks().unwrap() > before + 10,
            "the orphan is on the volume"
        );
        assert!(fs.stat(b"/.orphans").is_ok());
        assert_eq!(server::clean_orphans(&mut fs), Ok(1));
        // The directory of the orphans stays, a pair of blocks.
        assert_eq!(fs.used_blocks().unwrap(), before + 2);
        assert_eq!(server::clean_orphans(&mut fs), Ok(0));
        assert_eq!(fs.stat(b"/big"), Err(Error::NoEntry));
    }

    #[test]
    fn a_clone_shares_the_descriptions_and_their_positions() {
        let mut state = Storage::new();
        let mut t = Rig::new(&mut state);
        let (parent, child, other) = (1u64, 100u64, 2u64);
        let f = t.open(parent, b"/f", RW);
        let g = t.open(parent, b"/g", RW);
        let h = t.open(parent, b"/h", RW);
        t.write(parent, f, b"0123456789");
        t.seek(parent, f, 4, p::SEEK_SET).unwrap();
        // A clone with no label from the service is refused whole.
        assert_eq!(
            t.call(parent, 0, |w| p::clone(&[f], w)),
            Err(p::code(p::INVALID))
        );
        assert_eq!(t.server.session_count(), 1);
        let birth = word(&t.call(parent, child, |w| p::clone(&[f], w)).unwrap(), 0);
        assert_eq!(t.server.session_count(), 2);
        // More before the child has spoken; a session that is not the parent cannot.
        assert_eq!(
            t.call(other, 0, |w| p::clone_more(birth, &[f], w)),
            Err(p::code(p::BAD_HANDLE))
        );
        t.call(parent, 0, |w| p::clone_more(birth, &[g, f], w))
            .unwrap();
        // The child's handle numbers are the same, and the position is shared.
        assert_eq!(t.read(child, f, 3), b"456");
        assert_eq!(t.read(parent, f, 3), b"789");
        // The child has spoken: the birth is over. It holds f and g and has no h.
        assert_eq!(
            t.call(parent, 0, |w| p::clone_more(birth, &[h], w)),
            Err(p::code(p::BAD_HANDLE))
        );
        assert_eq!(
            t.call(child, 0, |w| p::read(h, 1, w)),
            Err(p::code(p::BAD_HANDLE))
        );
        // The parent closes f, g and h: f and g stay for the child; h goes.
        t.close(parent, f).unwrap();
        t.close(parent, g).unwrap();
        t.close(parent, h).unwrap();
        assert_eq!(t.server.open_count(), 2);
        assert_eq!(t.pread(child, f, 10, 0), b"0123456789");
        // The child goes: every reference it held goes with it.
        t.server.gone(&mut t.fs, child);
        assert_eq!((t.server.open_count(), t.server.node_count()), (0, 0));
        assert_eq!(t.server.session_count(), 2, "the parent and the other");
    }

    #[test]
    fn a_session_holds_a_bounded_number_of_descriptions() {
        let mut state = Storage::new();
        let mut t = Rig::new(&mut state);
        let mut held = Vec::new();
        for i in 0..p::HELD_MAX {
            held.push(t.open(1, std::format!("/f{i}").as_bytes(), RW));
        }
        assert_eq!(t.try_open(1, b"/more", RW), Err(p::code(p::TOO_MANY_OPEN)));
        // Another session still opens; a clone over the cap is refused, and a failed clone makes
        // no session and takes no reference.
        let other = t.open(2, b"/other", RW);
        let sessions = t.server.session_count();
        let refs_before = t.server.open_count();
        assert_eq!(
            t.call(2, 500, |w| p::clone(&[other, held[0]], w)),
            Err(p::code(p::BAD_HANDLE))
        );
        assert_eq!(t.server.session_count(), sessions);
        assert_eq!(t.server.open_count(), refs_before);
        t.close(1, held[0]).unwrap();
        assert!(t.try_open(1, b"/more", RW).is_ok());
    }

    #[test]
    fn a_pass_gives_a_description_to_whoever_adopts_it_once() {
        let mut state = Storage::new();
        let mut t = Rig::new(&mut state);
        let f = t.open(1, b"/f", RW);
        t.write(1, f, b"abcdef");
        t.seek(1, f, 2, p::SEEK_SET).unwrap();
        // Only a description the session holds can be exported.
        assert_eq!(
            t.call(2, 900, |w| p::handle_call(p::Method::Export, f, w)),
            Err(p::code(p::BAD_HANDLE))
        );
        t.call(1, 900, |w| p::handle_call(p::Method::Export, f, w))
            .unwrap();
        assert_eq!(t.server.pass_count(), 1);
        // The exporter lets go (exec): the pass keeps the description open.
        t.close(1, f).unwrap();
        assert_eq!((t.server.open_count(), t.server.node_count()), (1, 1));
        // An unknown label adopts nothing; the right one gives the description and its position.
        assert_eq!(t.call(3, 901, p::adopt), Err(p::code(p::BAD_HANDLE)));
        let adopted = t.call(3, 900, p::adopt).unwrap();
        let (handle, kind) = (word(&adopted, 0), word(&adopted, 4));
        assert_eq!(kind, p::KIND_FILE);
        assert_eq!(t.server.pass_count(), 0);
        assert_eq!(t.read(3, handle, 10), b"cdef");
        // Spent: a second adoption fails, and the session holds the one reference.
        assert_eq!(t.call(4, 900, p::adopt), Err(p::code(p::BAD_HANDLE)));
        t.close(3, handle).unwrap();
        assert_eq!(t.server.open_count(), 0);
    }

    #[test]
    fn an_unspent_pass_gives_its_reference_up_when_its_last_copy_goes() {
        let mut state = Storage::new();
        let mut t = Rig::new(&mut state);
        let f = t.open(1, b"/f", RW);
        t.call(1, 900, |w| p::handle_call(p::Method::Export, f, w))
            .unwrap();
        t.close(1, f).unwrap();
        assert_eq!(t.server.open_count(), 1);
        t.server.gone(&mut t.fs, 900);
        assert_eq!((t.server.open_count(), t.server.pass_count()), (0, 0));
        assert_eq!(t.server.node_count(), 0);
        // A session that adopts what it holds already keeps one reference.
        let g = t.open(1, b"/g", RW);
        t.call(1, 901, |w| p::handle_call(p::Method::Export, g, w))
            .unwrap();
        let again = t.call(1, 901, p::adopt).unwrap();
        assert_eq!(word(&again, 0), g);
        t.close(1, g).unwrap();
        assert_eq!(t.server.open_count(), 0);
        // Passes of one session are bounded.
        let h = t.open(1, b"/h", RW);
        for label in 0..p::PASSES_MAX as u64 {
            t.call(1, 1000 + label, |w| p::handle_call(p::Method::Export, h, w))
                .unwrap();
        }
        assert_eq!(
            t.call(1, 2000, |w| p::handle_call(p::Method::Export, h, w)),
            Err(Status::Kernel(abi::Error::LimitReached))
        );
    }

    #[test]
    fn a_handle_of_an_earlier_instance_is_stale_and_other_bad_handles_are_not() {
        let mut state = Storage::new();
        let mut t = Rig::new(&mut state);
        let f = t.open(1, b"/f", RW);
        assert_eq!(f >> 16, 7);
        // The service restarts: a new instance over the same volume, epoch 8.
        let mut next = Server::with_epoch(8);
        let ask = |s: &mut Server, fs: &mut Fs<'_, MemDevice>, h: u32| {
            let mut w = Writer::new();
            p::read(h, 1, &mut w).unwrap();
            p::reply(s.handle(fs, 1, 0, w.as_bytes()).as_bytes()).map(drop)
        };
        assert_eq!(ask(&mut next, &mut t.fs, f), Err(p::code(p::STALE)));
        // The new instance's own handle works, and the old one still does on the old instance.
        let mut w = Writer::new();
        p::open(b"/f", p::READ, &mut w).unwrap();
        let r = next.handle(&mut t.fs, 1, 0, w.as_bytes());
        let g = word(p::reply(r.as_bytes()).unwrap().bytes(8).unwrap(), 0);
        assert_eq!(g >> 16, 8);
        assert_eq!(ask(&mut next, &mut t.fs, g), Ok(()));
        assert_eq!(ask(&mut next, &mut t.fs, 0), Err(p::code(p::BAD_HANDLE)));
        assert_eq!(
            ask(&mut next, &mut t.fs, (8 << 16) | 99),
            Err(p::code(p::BAD_HANDLE))
        );
        // A handle that is current but held by another session is BAD_HANDLE.
        assert_eq!(
            t.call(2, 0, |w| p::read(f, 1, w)),
            Err(p::code(p::BAD_HANDLE))
        );
        // Epoch 0 is made 1.
        assert_eq!(Server::with_epoch(0).open_count(), 0);
    }

    #[test]
    fn a_request_of_version_one_is_refused() {
        let mut state = Storage::new();
        let mut t = Rig::new(&mut state);
        let mut w = Writer::new();
        proto_wire::Header::new(p::Method::Statfs.number(), 1)
            .write(&mut w)
            .unwrap();
        let reply = t.server.handle(&mut t.fs, 1, 0, w.as_bytes());
        assert_eq!(
            p::reply(reply.as_bytes()).map(drop),
            Err(Status::BadVersion)
        );
    }
}
