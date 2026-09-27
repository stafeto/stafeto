// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Per-process file descriptors for the first RAM file service. The three
//! standard descriptors use the console; file descriptors 3 and above
//! belong to one session with `ramfs`.

use crate::handle::{Channel, Handle};
use crate::{console, service, sys};
use abi::MESSAGE_MAX;
use proto_fs::{MAX_READ, MAX_WRITE, Method, valid_path};
use proto_uart::{ReadReply, ReadRequest, WriteReply, WriteRequest};
use proto_wire::{Reader, Status, Writer};

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
        if out.is_empty() {
            return Ok(0);
        }
        if fd == 0 {
            if let Some(uart) = &self.uart {
                let max = out.len().min(proto_uart::READ_MAX) as u32;
                let mut request = Writer::new();
                ReadRequest { max }.write(&mut request)?;
                let mut reply = [0; MESSAGE_MAX];
                let bytes = Self::call_on(uart, request.as_bytes(), &mut reply)?;
                let input = ReadReply::read(bytes, max)?.bytes;
                let mut echo = [0; proto_uart::READ_MAX];
                let mut echoed = 0;
                for (dst, &src) in out.iter_mut().zip(input) {
                    *dst = if src == b'\r' { b'\n' } else { src };
                    let visible = if src == b'\r' {
                        &b"\r\n"[..]
                    } else {
                        core::slice::from_ref(&src)
                    };
                    if echoed + visible.len() > echo.len() {
                        self.write(1, &echo[..echoed])?;
                        echoed = 0;
                    }
                    echo[echoed..echoed + visible.len()].copy_from_slice(visible);
                    echoed += visible.len();
                }
                if echoed > 0 {
                    self.write(1, &echo[..echoed])?;
                }
                return Ok(input.len());
            }
            let mut chars = [0; 8];
            loop {
                let n = console::poll(&mut chars).map_err(Status::Kernel)?;
                if n > 0 {
                    let n = n.min(out.len());
                    out[..n].copy_from_slice(&chars[..n]);
                    return Ok(n);
                }
                sys::yield_now().map_err(Status::Kernel)?;
            }
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
        if bytes.is_empty() {
            return Ok(0);
        }
        if fd == 1 || fd == 2 {
            if let Some(uart) = &self.uart {
                let chunk = &bytes[..bytes.len().min(proto_uart::WRITE_MAX)];
                let mut request = Writer::new();
                WriteRequest { bytes: chunk }.write(&mut request)?;
                let mut reply = [0; MESSAGE_MAX];
                let response = Self::call_on(uart, request.as_bytes(), &mut reply)?;
                return Ok(WriteReply::read(response)?.written as usize);
            }
            console::write(bytes).map_err(Status::Kernel)?;
            return Ok(bytes.len());
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

    pub fn fstat_size(&self, fd: u32) -> Result<u32, Status> {
        self.number(Method::Stat, fd, None)
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
