// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Typed handles that own their entry of the handle table (spec 5, 13.2).
//! A handle carries the kind of its object in its type, so that a channel
//! does not go where a thread is due. It is neither `Copy` nor `Clone`,
//! and it closes its entry when it goes out of scope. The ways out of
//! ownership take the handle: `close`, `into_raw`, and a send or a reply
//! that moves it (sys::send_handles, sys::Token::reply_handles). A program
//! so cannot use the value of a handle it closed or gave away (spec 5.4).
//! `from_raw` takes the ownership of a value, `borrowed` gives a view of
//! one that the program does not own; a stale value names no other object
//! (spec 5.1). Handles that came in a message wait in an `Incoming`.

use crate::sys;
use abi::{Error, MESSAGE_HANDLES, ObjectKind, Rights};
use core::fmt;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;

/// A handle to an object of kind `K`: `Channel`, `Timer`, `Process`,
/// `Thread`, `Resource`, `Memory`, `Interrupt`, or `Any` for one of any
/// kind.
#[repr(transparent)]
pub struct Handle<K> {
    raw: abi::Handle,
    kind: PhantomData<K>,
}

/// A channel (spec 6).
pub enum Channel {}
/// A timer (spec 10).
pub enum Timer {}
/// A process (spec 4).
pub enum Process {}
/// A thread (spec 8).
pub enum Thread {}
/// The system resource (spec 4).
pub enum Resource {}
/// A memory object (spec 7.3) or a device window (spec 9).
pub enum Memory {}
/// An interrupt binding (spec 9).
pub enum Interrupt {}
/// An object of any kind.
pub enum Any {}

/// A kind of object, as the info word of a handle that came in a message
/// names it (abi::msgbuf::info).
pub trait Kind {
    /// Whether a handle to an object of `kind` is a `Handle<Self>`.
    fn accepts(kind: ObjectKind) -> bool;
}

macro_rules! kinds {
    ($($marker:ident => $($kind:ident)|+;)*) => {
        $(impl Kind for $marker {
            fn accepts(kind: ObjectKind) -> bool {
                matches!(kind, $(ObjectKind::$kind)|+)
            }
        })*
    };
}

kinds! {
    Channel => Channel;
    Timer => Timer;
    Process => Process;
    Thread => Thread;
    Resource => Resource;
    Memory => Memory | DeviceWindow;
    Interrupt => Interrupt;
}

impl Kind for Any {
    fn accepts(_: ObjectKind) -> bool {
        true
    }
}

impl<K> Handle<K> {
    /// The handle with the value `raw`, which it owns from now on and
    /// closes when it goes; the kernel checks the kind at each call
    /// (WRONG_TYPE).
    pub const fn from_raw(raw: abi::Handle) -> Handle<K> {
        Handle {
            raw,
            kind: PhantomData,
        }
    }

    /// A view of the value `raw`, which the program owns elsewhere or not
    /// at all (a value in a static, x0 of a thread): nothing closes it.
    pub const fn borrowed(raw: abi::Handle) -> ManuallyDrop<Handle<K>> {
        ManuallyDrop::new(Handle::from_raw(raw))
    }

    /// The value the kernel knows the handle by.
    pub const fn raw(&self) -> abi::Handle {
        self.raw
    }

    /// The value, which nothing closes any more: whoever gets it answers
    /// for it.
    pub fn into_raw(self) -> abi::Handle {
        ManuallyDrop::new(self).raw
    }

    /// The same handle with its kind forgotten, to go into a message.
    pub fn erase(self) -> Handle<Any> {
        Handle::from_raw(self.into_raw())
    }
}

impl<K> Drop for Handle<K> {
    /// handle_close; what it returns is not looked at.
    fn drop(&mut self) {
        let _ = sys::close_raw(self.raw);
    }
}

impl<K> PartialEq for Handle<K> {
    fn eq(&self, other: &Handle<K>) -> bool {
        self.raw == other.raw
    }
}

impl<K> Eq for Handle<K> {}

impl<K> fmt::Debug for Handle<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw.fmt(f)
    }
}

/// The handles that came with a message (spec 6.1, 6.2), at most
/// abi::MESSAGE_HANDLES, each with the kind of its object and its rights
/// from its info word. `take` hands one out; those that nobody took close
/// when the `Incoming` goes, so a message with handles its receiver did
/// not ask for leaves no entries in its table (spec 5.4).
#[derive(PartialEq, Eq)]
pub struct Incoming {
    count: usize,
    /// The values; abi::Handle::INVALID once taken.
    values: [abi::Handle; MESSAGE_HANDLES],
    info: [(ObjectKind, Rights); MESSAGE_HANDLES],
}

impl Incoming {
    /// No handles.
    pub const fn none() -> Incoming {
        Incoming {
            count: 0,
            values: [abi::Handle::INVALID; MESSAGE_HANDLES],
            info: [(ObjectKind::Unknown(0), Rights::NONE); MESSAGE_HANDLES],
        }
    }

    /// The `count` handles the kernel wrote into the calling thread's
    /// message buffer with the message that came last (msgbuf::handle).
    pub(crate) fn from_buffer(count: usize) -> Incoming {
        let mut incoming = Incoming::none();
        incoming.count = count.min(MESSAGE_HANDLES);
        for i in 0..incoming.count {
            (incoming.values[i], incoming.info[i]) = crate::msgbuf::handle(i);
        }
        incoming
    }

    /// The count of handles that came, taken or not.
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The kind and the rights of handle `i`, as they came; None past the
    /// count.
    pub fn info(&self, i: usize) -> Option<(ObjectKind, Rights)> {
        (i < self.count).then(|| self.info[i])
    }

    /// Handle `i`, when its object is of kind `K`: WRONG_TYPE, with no call
    /// to the kernel, when it is not, and the handle stays here;
    /// BAD_HANDLE past the count or when it was taken.
    pub fn take<K: Kind>(&mut self, i: usize) -> Result<Handle<K>, Error> {
        let (kind, _) = self.info(i).ok_or(Error::BadHandle)?;
        if self.values[i] == abi::Handle::INVALID {
            return Err(Error::BadHandle);
        }
        if !K::accepts(kind) {
            return Err(Error::WrongType);
        }
        let raw = core::mem::replace(&mut self.values[i], abi::Handle::INVALID);
        Ok(Handle::from_raw(raw))
    }

    /// Handle `i`, of any kind; BAD_HANDLE past the count or when it was
    /// taken.
    pub fn take_any(&mut self, i: usize) -> Result<Handle<Any>, Error> {
        self.take::<Any>(i)
    }
}

impl Drop for Incoming {
    /// Closes the handles nobody took.
    fn drop(&mut self) {
        for i in 0..self.count {
            if self.values[i] != abi::Handle::INVALID {
                drop(Handle::<Any>::from_raw(self.values[i]));
            }
        }
    }
}

impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(&self.values[..self.count]).finish()
    }
}
