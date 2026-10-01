// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Per-process file descriptors for the first RAM file service. The three
//! standard descriptors use the console; file descriptors 3 and above
//! belong to one session with `ramfs`.

use crate::handle::{Channel, Handle};
use crate::{console, service, sys};
use abi::{Error, MESSAGE_MAX};
use proto_fs::{MAX_READ, MAX_WRITE, Metadata, Method, valid_path};
use proto_uart::{ReadReply, ReadRequest, WriteReply, WriteRequest};
use proto_wire::{Reader, Status, Writer};

/// A console transport snapshot, without a borrow of the file owner.
/// It carries no application buffer or file-state pointer. The owning Files
/// must remain alive while this snapshot is used; it does not retain a UART
/// session. A closed or failed transport is reported by the kernel.
#[derive(Clone, Copy)]
pub struct Input {
    uart: Option<abi::Handle>,
}

impl Input {
    /// A process-local transport identifier for value-message routing.
    pub fn uart(&self) -> Option<abi::Handle> {
        self.uart
    }

    /// Borrow a transport retained elsewhere in this process; no ownership is taken.
    pub const fn from_uart(uart: Option<abi::Handle>) -> Self {
        Self { uart }
    }

    /// A plain READ (proto_uart): the reply waits for input. A program
    /// with signals reads in two steps instead (posix-abi), so that a
    /// signal never waits behind it.
    pub fn read(&self, out: &mut [u8]) -> Result<usize, Status> {
        if out.is_empty() {
            return Ok(0);
        }
        let Some(raw) = self.uart else {
            // No console's driver to read from: input has no transport.
            return Err(Status::Kernel(Error::BadHandle));
        };
        let uart = Handle::<Channel>::borrowed(raw);
        let max = out.len().min(proto_uart::READ_MAX) as u32;
        let mut request = Writer::new();
        ReadRequest { max }.write(&mut request)?;
        let mut reply = [0; MESSAGE_MAX];
        let bytes = Files::call_on(&uart, request.as_bytes(), &mut reply)?;
        let input = ReadReply::read(bytes, max)?.bytes;
        Ok(self.deliver(input, out))
    }

    /// Bytes `input` the console gave: into `out` with CR as LF, and their
    /// echo back to the console (CR as CR LF); the count.
    pub fn deliver(&self, input: &[u8], out: &mut [u8]) -> usize {
        let uart = self.uart.map(Handle::<Channel>::borrowed);
        let mut echo = [0; proto_uart::READ_MAX];
        let mut echoed = 0;
        for (dst, &src) in out.iter_mut().zip(input) {
            *dst = if src == b'\r' { b'\n' } else { src };
        }
        // Data has already been delivered. Echo failure cannot turn this
        // successful read into an error and lose its bytes.
        for &src in input {
            let visible = if src == b'\r' {
                &b"\r\n"[..]
            } else {
                core::slice::from_ref(&src)
            };
            if echoed + visible.len() > echo.len() {
                if console_write(uart.as_deref(), &echo[..echoed]).is_err() {
                    return input.len().min(out.len());
                }
                echoed = 0;
            }
            echo[echoed..echoed + visible.len()].copy_from_slice(visible);
            echoed += visible.len();
        }
        if echoed > 0 {
            let _ = console_write(uart.as_deref(), &echo[..echoed]);
        }
        input.len().min(out.len())
    }
}

pub struct Files {
    channel: Handle<Channel>,
    uart: Option<Handle<Channel>>,
}

impl Files {
    pub fn connect(parent: &Handle<Channel>) -> Result<Self, Status> {
        Ok(Self {
            channel: service::connect(parent, "ramfs")?,
            uart: None,
        })
    }

    pub fn connect_with_uart(parent: &Handle<Channel>) -> Result<Self, Status> {
        Ok(Self {
            channel: service::connect(parent, "ramfs")?,
            uart: Some(service::connect(parent, "uart")?),
        })
    }

    /// Snapshot the input endpoint; this Files retains its UART session.
    pub fn input(&self) -> Input {
        Input {
            uart: self.uart.as_ref().map(Handle::raw),
        }
    }

    pub fn has_uart(&self) -> bool {
        self.uart.is_some()
    }

    fn call<'a>(
        &self,
        request: &[u8],
        buffer: &'a mut [u8; MESSAGE_MAX],
    ) -> Result<&'a [u8], Status> {
        Self::call_on(&self.channel, request, buffer)
    }

    fn call_on<'a>(
        channel: &Handle<Channel>,
        request: &[u8],
        buffer: &'a mut [u8; MESSAGE_MAX],
    ) -> Result<&'a [u8], Status> {
        let reply = sys::send(channel, request).map_err(Status::Kernel)?;
        let bytes = reply.bytes(buffer);
        match Status::from_code(Reader::new(bytes).u32()?) {
            Status::Ok => Ok(bytes),
            status => Err(status),
        }
    }

    fn number(&self, method: Method, fd: u32, second: Option<u32>) -> Result<u32, Status> {
        let mut w = Writer::new();
        method.header().write(&mut w)?;
        w.u32(fd)?;
        if let Some(second) = second {
            w.u32(second)?;
        }
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.call(w.as_bytes(), &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let value = r.u32()?;
        r.finish()?;
        Ok(value)
    }

    pub fn open(&self, path: &str, flags: u32) -> Result<u32, Status> {
        valid_path(path.as_bytes())?;
        let mut w = Writer::new();
        Method::Open.header().write(&mut w)?;
        w.u32(flags)?;
        w.bytes(path.as_bytes())?;
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.call(w.as_bytes(), &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let fd = r.u32()?;
        r.finish()?;
        Ok(fd)
    }

    pub fn read(&self, fd: u32, out: &mut [u8]) -> Result<usize, Status> {
        if fd == 0 {
            return self.input().read(out);
        }
        let mut w = Writer::new();
        Method::Read.header().write(&mut w)?;
        w.u32(fd)?;
        w.u32(out.len().min(MAX_READ) as u32)?;
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.call(w.as_bytes(), &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let n = r.u32()? as usize;
        if n > out.len() || n > MAX_READ {
            return Err(Status::BadSize);
        }
        out[..n].copy_from_slice(r.bytes(n)?);
        r.finish()?;
        Ok(n)
    }

    pub fn write(&self, fd: u32, bytes: &[u8]) -> Result<usize, Status> {
        if bytes.is_empty() && (fd == 1 || fd == 2) {
            return Ok(0);
        }
        if fd == 1 || fd == 2 {
            return console_write(self.uart.as_ref(), bytes);
        }
        let bytes = &bytes[..bytes.len().min(MAX_WRITE)];
        let mut w = Writer::new();
        Method::Write.header().write(&mut w)?;
        w.u32(fd)?;
        w.bytes(bytes)?;
        Ok(self.number_from_written(w.as_bytes())? as usize)
    }

    fn number_from_written(&self, request: &[u8]) -> Result<u32, Status> {
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.call(request, &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let n = r.u32()?;
        r.finish()?;
        Ok(n)
    }

    pub fn lseek(&self, fd: u32, offset: u32) -> Result<u32, Status> {
        self.number(Method::Seek, fd, Some(offset))
    }

    /// Signed, 64-bit seek with an origin. The service owns the offset.
    pub fn seek_from(
        &self,
        fd: u32,
        offset: i64,
        origin: proto_fs::SeekFrom,
    ) -> Result<i64, Status> {
        let mut w = Writer::new();
        Method::SeekFrom.header().write(&mut w)?;
        w.u32(fd)?;
        w.u64(offset as u64)?;
        w.u32(origin as u32)?;
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.call(w.as_bytes(), &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let offset = i64::try_from(r.u64()?).map_err(|_| Status::BadSize)?;
        r.finish()?;
        Ok(offset)
    }

    pub fn fstat_size(&self, fd: u32) -> Result<u32, Status> {
        self.number(Method::Stat, fd, None)
    }

    /// Read one directory entry by index. Kind 1 is a directory, 2 a file.
    pub fn read_dir(
        &self,
        path: &str,
        index: u32,
        out: &mut [u8],
    ) -> Result<Option<(usize, u32)>, Status> {
        valid_path(path.as_bytes())?;
        let mut w = Writer::new();
        Method::ReadDir.header().write(&mut w)?;
        w.u32(index)?;
        w.bytes(path.as_bytes())?;
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.call(w.as_bytes(), &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let kind = r.u32()?;
        let name = r.bytes(r.left())?;
        if kind == 0 {
            return if name.is_empty() {
                Ok(None)
            } else {
                Err(Status::BadSize)
            };
        }
        if !(1..=2).contains(&kind) || name.is_empty() || name.len() > out.len() {
            return Err(Status::BadSize);
        }
        out[..name.len()].copy_from_slice(name);
        Ok(Some((name.len(), kind)))
    }

    /// Read one entry and advance the shared service-owned directory offset.
    pub fn read_dir_fd(
        &self,
        fd: u32,
        out: &mut [u8],
    ) -> Result<Option<(usize, u32, u64)>, Status> {
        let mut w = Writer::new();
        Method::ReadDirFd.header().write(&mut w)?;
        w.u32(fd)?;
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.call(w.as_bytes(), &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let Some(entry) = proto_fs::DirectoryEntry::read(&mut r)? else {
            return Ok(None);
        };
        if entry.name.len() > out.len() {
            return Err(Status::BadSize);
        }
        out[..entry.name.len()].copy_from_slice(entry.name);
        Ok(Some((entry.name.len(), entry.kind, entry.inode)))
    }

    pub fn lookup(&self, path: &str) -> Result<Metadata, Status> {
        valid_path(path.as_bytes())?;
        let mut w = Writer::new();
        Method::Lookup.header().write(&mut w)?;
        w.bytes(path.as_bytes())?;
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.call(w.as_bytes(), &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let metadata = Metadata {
            kind: r.u32()?,
            size: r.u32()?,
        };
        if !(1..=2).contains(&metadata.kind) {
            return Err(Status::BadSize);
        }
        r.finish()?;
        Ok(metadata)
    }

    pub fn node_information(&self, path: &str) -> Result<proto_fs::NodeInfo, Status> {
        valid_path(path.as_bytes())?;
        let mut w = Writer::new();
        Method::InfoPath.header().write(&mut w)?;
        w.bytes(path.as_bytes())?;
        self.information(w.as_bytes())
    }

    pub fn descriptor_information(&self, fd: u32) -> Result<proto_fs::NodeInfo, Status> {
        let mut w = Writer::new();
        Method::InfoFd.header().write(&mut w)?;
        w.u32(fd)?;
        self.information(w.as_bytes())
    }

    fn information(&self, request: &[u8]) -> Result<proto_fs::NodeInfo, Status> {
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.call(request, &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let info = proto_fs::NodeInfo::read(&mut r)?;
        r.finish()?;
        Ok(info)
    }

    pub fn close(&self, fd: u32) -> Result<(), Status> {
        let mut w = Writer::new();
        Method::Close.header().write(&mut w)?;
        w.u32(fd)?;
        let mut reply = [0; MESSAGE_MAX];
        let bytes = self.call(w.as_bytes(), &mut reply)?;
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        r.finish()
    }
}

fn console_write(uart: Option<&Handle<Channel>>, bytes: &[u8]) -> Result<usize, Status> {
    if let Some(uart) = uart {
        let chunk = &bytes[..bytes.len().min(proto_uart::WRITE_MAX)];
        let mut request = Writer::new();
        WriteRequest { bytes: chunk }.write(&mut request)?;
        let mut reply = [0; MESSAGE_MAX];
        let response = Files::call_on(uart, request.as_bytes(), &mut reply)?;
        return Ok(WriteReply::read(response)?.written as usize);
    }
    console::write(bytes).map_err(Status::Kernel)?;
    Ok(bytes.len())
}
