// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Initial image objects retained for a later image query or fork.

use super::{access, first_thread};
use crate::handle::{Handle, Memory, Process, Thread};
use crate::sys;
use abi::{Access, Error, INIT_STACK_TOP, Policy, Rights};
use bootimg::{PAGE_SIZE, Part, Program, Segment};
use core::mem::ManuallyDrop;

/// A target range and whether its mapping was installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub addr: u64,
    pub pages: u64,
    pub access: Access,
    pub installed: bool,
}

/// The caller's mapping whose successful unmap must precede window reuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowMapping {
    pub process: abi::Handle,
    pub memory: abi::Handle,
    pub addr: usize,
    pub len: u64,
}

/// A retained object with READ, optional WRITE, DUPLICATE and TRANSFER.
pub struct RetainedSegment {
    pub mapping: Mapping,
    memory: Option<Handle<Memory>>,
}

impl RetainedSegment {
    pub fn memory(&self) -> Option<&Handle<Memory>> {
        self.memory.as_ref()
    }

    pub fn into_memory(self) -> Option<Handle<Memory>> {
        self.memory
    }
}

/// All nonempty program segments and its stack, with a stopped first thread.
pub struct RetainedImage {
    pub segments: [Option<RetainedSegment>; 4],
    pub thread: Handle<Thread>,
}

struct PartialFill {
    segments: [Option<RetainedSegment>; 4],
    broad: Option<Handle<Memory>>,
    temporary: Option<Handle<Memory>>,
    pending: Option<Mapping>,
    window: Option<WindowMapping>,
    thread: Option<Handle<Thread>>,
}

impl PartialFill {
    fn new() -> Self {
        Self {
            segments: core::array::from_fn(|_| None),
            broad: None,
            temporary: None,
            pending: None,
            window: None,
            thread: None,
        }
    }

    fn failed(self, error: Error) -> FillFailure {
        FillFailure {
            error,
            state: ManuallyDrop::new(self),
        }
    }
}

/// Partial custody survives dropping this value. The caller must retain it
/// until explicit cleanup and keep the target process stopped. Target
/// mappings remain until their own unmap or the confirmed end of that process.
#[must_use]
pub struct FillFailure {
    pub error: Error,
    state: ManuallyDrop<PartialFill>,
}

impl FillFailure {
    pub fn window(&self) -> Option<WindowMapping> {
        self.state.window
    }

    pub fn pending_mapping(&self) -> Option<Mapping> {
        self.state.pending
    }

    pub fn segments(&self) -> &[Option<RetainedSegment>; 4] {
        &self.state.segments
    }

    /// Unmaps the caller's live window first, then closes at most one local
    /// handle per call. An error preserves that handle and the window state.
    /// A true result concerns local custody alone; target mappings are
    /// recorded separately and need the caller's target cleanup.
    ///
    /// # Safety
    /// The window remains exclusive and unused, with the same live owning
    /// process as during `fill_retained`. The target's first thread stays stopped.
    pub unsafe fn cleanup_one(&mut self, own: &Handle<Process>) -> Result<bool, Error> {
        let state = &mut *self.state;
        if let Some(window) = state.window {
            if own.raw() != window.process {
                return Err(Error::InvalidArgs);
            }
            // SAFETY: the window is still exclusively held by this state.
            unsafe { sys::mem_unmap(own, window.addr, window.len) }?;
            state.window = None;
            return Ok(false);
        }
        if state.temporary.is_some() {
            close_owned(&mut state.temporary)?;
            return Ok(false);
        }
        if state.broad.is_some() {
            close_owned(&mut state.broad)?;
            return Ok(false);
        }
        for segment in &mut state.segments {
            if let Some(held) = segment
                && held.memory.is_some()
            {
                close_owned(&mut held.memory)?;
                return Ok(false);
            }
        }
        if state.thread.is_some() {
            close_owned(&mut state.thread)?;
            return Ok(false);
        }
        Ok(true)
    }
}

fn close_owned<K>(slot: &mut Option<Handle<K>>) -> Result<(), Error> {
    if let Some(handle) = slot {
        sys::close_raw(handle.raw())?;
        let _ = slot.take().expect("owned handle").into_raw();
    }
    Ok(())
}

/// Fills a stopped process and retains each original Memory object. Code
/// objects retain MAP_READ, DUPLICATE and TRANSFER. Writable objects also
/// retain MAP_WRITE. The target mapping uses a separate access-only handle.
/// Every failed operation returns its preceding custody and live window.
///
/// # Safety
/// The promises of `super::fill` apply. The target process is empty and
/// stopped, and the window stays exclusive until a returned failure has
/// confirmed its own-window cleanup. The caller keeps both process handles
/// live until partial cleanup and separately confirms the target's end.
#[allow(clippy::result_large_err)] // The fixed error state owns every partial object.
pub unsafe fn fill_retained(
    own: &Handle<Process>,
    process: &Handle<Process>,
    program: &Program<'_>,
    window: usize,
    priority: u8,
    policy: Policy,
) -> Result<RetainedImage, FillFailure> {
    let mut state = PartialFill::new();
    let mut next = 0;
    for part in Part::ALL {
        let segment = &program.segments[part as usize];
        if segment.mem_size == 0 {
            continue;
        }
        // SAFETY: the exclusive window and stopped target are the caller's promise.
        if let Err(error) = unsafe {
            place_retained(
                &mut state,
                next,
                own,
                process,
                segment,
                access(part),
                window,
            )
        } {
            return Err(state.failed(error));
        }
        next += 1;
    }
    let stack = u64::from(program.stack_size);
    let segment = Segment {
        vaddr: INIT_STACK_TOP - stack,
        mem_size: stack,
        bytes: &[],
    };
    // SAFETY: the same caller promise; successful segments cleared the window.
    if let Err(error) = unsafe {
        place_retained(
            &mut state,
            next,
            own,
            process,
            &segment,
            Access::ReadWrite,
            window,
        )
    } {
        return Err(state.failed(error));
    }
    match first_thread(process, program.entry, priority, policy) {
        Ok(thread) => state.thread = Some(thread),
        Err(error) => return Err(state.failed(error)),
    }
    Ok(RetainedImage {
        segments: state.segments,
        thread: state.thread.expect("created first thread"),
    })
}

#[allow(clippy::too_many_arguments)]
unsafe fn place_retained(
    state: &mut PartialFill,
    slot: usize,
    own: &Handle<Process>,
    process: &Handle<Process>,
    segment: &Segment<'_>,
    access: Access,
    window: usize,
) -> Result<(), Error> {
    let range = segment.pages();
    let len = range.end - range.start;
    state.pending = Some(Mapping {
        addr: range.start,
        pages: len / PAGE_SIZE,
        access,
        installed: false,
    });
    state.broad = Some(sys::mem_create(len)?);
    let broad = state.broad.as_ref().expect("created memory");
    if !segment.bytes.is_empty() {
        let len = (segment.bytes.len() as u64).next_multiple_of(PAGE_SIZE);
        sys::mem_map(own, broad, 0, len, window, Access::ReadWrite)?;
        state.window = Some(WindowMapping {
            process: own.raw(),
            memory: broad.raw(),
            addr: window,
            len,
        });
        // SAFETY: this exclusive window maps enough writable bytes of broad.
        unsafe {
            core::ptr::copy_nonoverlapping(
                segment.bytes.as_ptr(),
                window as *mut u8,
                segment.bytes.len(),
            )
        };
        // SAFETY: nothing uses the copied window now; its state survives failure.
        unsafe { sys::mem_unmap(own, window, len) }?;
        state.window = None;
    }
    state.temporary = Some(sys::handle_duplicate(broad, access.rights())?);
    sys::mem_map(
        process,
        state.temporary.as_ref().expect("target memory"),
        0,
        len,
        range.start as usize,
        access,
    )?;
    state.pending.as_mut().expect("pending mapping").installed = true;
    close_owned(&mut state.temporary)?;
    let mut rights = Rights::MAP_READ | Rights::DUPLICATE | Rights::TRANSFER;
    if access == Access::ReadWrite {
        rights = rights | Rights::MAP_WRITE;
    }
    let retained = sys::handle_duplicate(state.broad.as_ref().expect("broad memory"), rights)?;
    state.segments[slot] = Some(RetainedSegment {
        mapping: state.pending.take().expect("installed mapping"),
        memory: Some(retained),
    });
    close_owned(&mut state.broad)
}
