// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Bounded RAM files and per-client open descriptions for the first POSIX
//! userspace experiment. A single service thread owns `Ram`; each IPC
//! session owns its own `Fds`, so closing a session closes its files.

#![cfg_attr(not(test), no_std)]

use proto_fs::{BAD_FD, NO_ENTRY, NO_SPACE, READ_ONLY, READ_WRITE, WRITE_ONLY};

const FILE_CAPACITY: usize = 1024;
const OPEN_MAX: usize = 8;
const MOTD: &[u8] = b"stafeto ramfs\n";

#[derive(Clone, Copy)]
enum File {
    Motd,
    Scratch,
}

#[derive(Clone, Copy)]
struct Open {
    file: File,
    offset: usize,
    flags: u32,
}

pub struct Fds {
    open: [Option<Open>; OPEN_MAX],
}

impl Default for Fds {
    fn default() -> Self {
        Self {
            open: [None; OPEN_MAX],
        }
    }
}

impl Fds {
    pub fn open(&mut self, path: &str, flags: u32) -> Result<u32, u32> {
        if flags > READ_WRITE {
            return Err(proto_wire::BAD_SIZE);
        }
        let file = match path {
            "/etc/motd" if flags == READ_ONLY => File::Motd,
            "/etc/motd" => return Err(proto_wire::BAD_SIZE),
            "/tmp/probe" => File::Scratch,
            _ => return Err(NO_ENTRY),
        };
        let slot = self
            .open
            .iter_mut()
            .position(|fd| fd.is_none())
            .ok_or(NO_SPACE)?;
        self.open[slot] = Some(Open {
            file,
            offset: 0,
            flags,
        });
        Ok(slot as u32 + 3)
    }

    fn get(&self, fd: u32) -> Result<Open, u32> {
        let slot = fd.checked_sub(3).ok_or(BAD_FD)? as usize;
        self.open.get(slot).and_then(|fd| *fd).ok_or(BAD_FD)
    }

    fn get_mut(&mut self, fd: u32) -> Result<&mut Open, u32> {
        let slot = fd.checked_sub(3).ok_or(BAD_FD)? as usize;
        self.open
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(BAD_FD)
    }

    pub fn close(&mut self, fd: u32) -> Result<(), u32> {
        self.get(fd)?;
        self.open[(fd - 3) as usize] = None;
        Ok(())
    }

    pub fn seek(&mut self, fd: u32, offset: u32) -> Result<u32, u32> {
        let open = self.get_mut(fd)?;
        open.offset = offset as usize;
        Ok(offset)
    }
}

pub struct Ram {
    scratch: [u8; FILE_CAPACITY],
    len: usize,
}

impl Default for Ram {
    fn default() -> Self {
        Self {
            scratch: [0; FILE_CAPACITY],
            len: 0,
        }
    }
}

impl Ram {
    fn bytes(&self, file: File) -> &[u8] {
        match file {
            File::Motd => MOTD,
            File::Scratch => &self.scratch[..self.len],
        }
    }

    pub fn size(&self, fds: &Fds, fd: u32) -> Result<u32, u32> {
        Ok(self.bytes(fds.get(fd)?.file).len() as u32)
    }

    pub fn read(&self, fds: &mut Fds, fd: u32, out: &mut [u8]) -> Result<usize, u32> {
        let open = fds.get_mut(fd)?;
        if open.flags == WRITE_ONLY {
            return Err(proto_wire::BAD_SIZE);
        }
        let bytes = self.bytes(open.file);
        let start = open.offset.min(bytes.len());
        let n = out.len().min(bytes.len() - start);
        out[..n].copy_from_slice(&bytes[start..start + n]);
        open.offset = open.offset.saturating_add(n);
        Ok(n)
    }

    pub fn write(&mut self, fds: &mut Fds, fd: u32, bytes: &[u8]) -> Result<usize, u32> {
        let open = fds.get_mut(fd)?;
        if open.flags == READ_ONLY || matches!(open.file, File::Motd) {
            return Err(proto_wire::BAD_SIZE);
        }
        let end = open.offset.checked_add(bytes.len()).ok_or(NO_SPACE)?;
        if end > FILE_CAPACITY {
            return Err(NO_SPACE);
        }
        if open.offset > self.len {
            self.scratch[self.len..open.offset].fill(0);
        }
        self.scratch[open.offset..end].copy_from_slice(bytes);
        self.len = self.len.max(end);
        open.offset = end;
        Ok(bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_have_independent_offsets_and_close_invalidates_fd() {
        let ram = Ram::default();
        let mut a = Fds::default();
        let mut b = Fds::default();
        let fa = a.open("/etc/motd", READ_ONLY).unwrap();
        let fb = b.open("/etc/motd", READ_ONLY).unwrap();
        let mut out = [0; 7];
        assert_eq!(ram.read(&mut a, fa, &mut out), Ok(7));
        assert_eq!(&out, b"stafeto");
        assert_eq!(ram.read(&mut b, fb, &mut out), Ok(7));
        assert_eq!(&out, b"stafeto");
        assert_eq!(a.close(fa), Ok(()));
        assert_eq!(ram.read(&mut a, fa, &mut out), Err(BAD_FD));
        assert_eq!(ram.size(&b, fb), Ok(MOTD.len() as u32));
    }

    #[test]
    fn write_seek_read_and_no_space_leave_file_intact() {
        let mut ram = Ram::default();
        let mut fds = Fds::default();
        let fd = fds.open("/tmp/probe", READ_WRITE).unwrap();
        assert_eq!(ram.write(&mut fds, fd, b"abc"), Ok(3));
        assert_eq!(fds.seek(fd, 1), Ok(1));
        assert_eq!(ram.write(&mut fds, fd, b"Z"), Ok(1));
        assert_eq!(ram.size(&fds, fd), Ok(3));
        assert_eq!(fds.seek(fd, FILE_CAPACITY as u32), Ok(FILE_CAPACITY as u32));
        assert_eq!(ram.write(&mut fds, fd, b"overflow"), Err(NO_SPACE));
        assert_eq!(ram.size(&fds, fd), Ok(3));
        assert_eq!(fds.seek(fd, 0), Ok(0));
        let mut out = [0; 3];
        assert_eq!(ram.read(&mut fds, fd, &mut out), Ok(3));
        assert_eq!(&out, b"aZc");
    }
}
