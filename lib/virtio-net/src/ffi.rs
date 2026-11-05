// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The library for a C program that owns the second network device (spec
//! 6, 3.9; `include/vnet.h`): `stafeto_fast_claim` of the C library maps
//! the window and the objects and fills `struct stafeto_fast_claim`
//! (`Claim`), and these functions drive the device from it. The program's
//! process has one device, slot 0 of `host`; it has two queues on the
//! object `dma1` and 8 192 buffers of 2 KiB on the four objects of 4 MiB,
//! in one pool that receiving and sending share.
//!
//! The functions are for one thread: the state is a static of the library,
//! and nothing locks it. The library makes no call of the kernel; the line
//! of the device stays with the network service, which tells the owner of
//! an interrupt (`stafeto_fast_wait`). `vnet_lost` reads the device's
//! status: a reset that the owner did not make (the network service ended,
//! and init stopped the device) says the device is gone.
//!
//! A static library for a C program has no `rt` and no `_start`: the C
//! library has them. A panic calls `abort` of the C library.

use crate::books::QUEUE_SIZE;
use crate::frames::{BUFFER_LEN, HDR_LEN, MAX_FRAME, fill_sums, rx_frame, tx_prepare};
use crate::host::{self, Host, Region};
use crate::open::{MAC, MTU, STATUS};
use crate::transport::{self, Snapshot};
use crate::{barrier, open};
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_void};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use proto_net::fast::{
    FRAME_MAX, RING_SLOTS, TO_OWNER, TO_SERVICE, head_offset, len_offset, slot_offset, tail_offset,
};
use virtio_drivers::queue::VirtQueue;
use virtio_drivers::transport::{DeviceStatus, SomeTransport, Transport};

/// `struct stafeto_fast_object` of `<stafeto/fast.h>`: where the C
/// library mapped an object, where it lies for the device, its pages.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Object {
    pub va: u64,
    pub pa: u64,
    pub pages: u32,
    pub uncached: u32,
}

/// `struct stafeto_fast_config`: the second address.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Config {
    pub address: [u8; 4],
    pub gateway: [u8; 4],
    pub dns: [u8; 4],
    pub mac: [u8; 6],
    pub prefix: u8,
    pub pad: u8,
}

/// `struct stafeto_fast_claim`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Claim {
    /// 1 virtio-mmio, 2 Virtio PCI.
    pub kind: u32,
    pub pad: u32,
    /// Where the transport's registers are (virtio-mmio), or BAR 0 (PCI).
    pub window: u64,
    /// The bytes of BAR 0 mapped at `window` (PCI).
    pub window_len: u64,
    /// `dma1`, `net1a` to `net1d`.
    pub objects: [Object; 5],
    /// The bypass ring (`proto_net::fast`).
    pub ring: u64,
    pub bar_sizes: [u64; 6],
    pub snapshot: [u32; 64],
    pub config: Config,
}

const _: () = {
    // The layout of the header.
    assert!(core::mem::size_of::<Object>() == 24);
    assert!(core::mem::size_of::<Config>() == 20);
    assert!(core::mem::offset_of!(Claim, objects) == 24);
    assert!(core::mem::offset_of!(Claim, ring) == 144);
    assert!(core::mem::offset_of!(Claim, snapshot) == 200);
    assert!(core::mem::offset_of!(Claim, config) == 456);
    assert!(core::mem::size_of::<Claim>() == 480);
};

/// `struct vnet_buf`: a received frame, in buffer `buf`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Buf {
    pub buf: u32,
    pub len: u32,
    pub frame: *mut c_void,
}

/// No buffer (`VNET_NONE`).
pub const NONE: u32 = u32::MAX;
/// The buffers of a pool of four objects of 4 MiB.
pub const BUFFERS: usize = 4 * PER_OBJECT;
const PER_OBJECT: usize = (4 << 20) / BUFFER_LEN;
/// The queues: `receiveq` and `transmitq` (Virtio 1.2, 5.1.2).
const RECEIVEQ: u16 = 0;
const TRANSMITQ: u16 = 1;
const PAGE: usize = 4096;

/// Why `vnet_open` failed (negative returns).
pub const NO_OBJECTS: c_int = -1;
pub const NO_TRANSPORT: c_int = -2;
pub const REFUSED: c_int = -3;
pub const NO_QUEUES: c_int = -4;

type Queue = VirtQueue<Host<0>, QUEUE_SIZE>;

/// The pool of buffers: their numbers, free ones first.
pub struct Pool {
    bases: [usize; 4],
    free: [u32; BUFFERS],
    free_len: usize,
}

impl Pool {
    /// Every buffer free. The pool hands them out across the four objects
    /// in turn, so that the queue of receiving holds buffers of each from
    /// the start (and a wrong address of any object shows at once).
    fn fill(&mut self, bases: [usize; 4]) {
        self.bases = bases;
        for (i, slot) in self.free.iter_mut().enumerate() {
            let k = BUFFERS - 1 - i;
            *slot = ((k % 4) * PER_OBJECT + k / 4) as u32;
        }
        self.free_len = BUFFERS;
    }

    /// Where buffer `n` starts: in object `n / PER_OBJECT`, as the device
    /// sees four objects that need not lie together.
    pub fn at(&self, n: u32) -> Option<usize> {
        let n = n as usize;
        let base = *self.bases.get(n / PER_OBJECT)?;
        Some(base + (n % PER_OBJECT) * BUFFER_LEN)
    }

    fn take(&mut self) -> Option<u32> {
        self.free_len = self.free_len.checked_sub(1)?;
        Some(self.free[self.free_len])
    }

    fn give(&mut self, n: u32) {
        if (n as usize) < BUFFERS && self.free_len < BUFFERS {
            self.free[self.free_len] = n;
            self.free_len += 1;
        }
    }
}

struct State {
    transport: SomeTransport<'static>,
    rx: Queue,
    tx: Queue,
    rx_of: [u32; QUEUE_SIZE],
    tx_of: [u32; QUEUE_SIZE],
    rx_dirty: bool,
    tx_dirty: bool,
    ring: usize,
}

struct Cell<T>(UnsafeCell<MaybeUninit<T>>);
// SAFETY: the library is for one thread (module comment).
unsafe impl<T> Sync for Cell<T> {}

static STATE: Cell<State> = Cell(UnsafeCell::new(MaybeUninit::uninit()));
static POOL: Cell<Pool> = Cell(UnsafeCell::new(MaybeUninit::zeroed()));
static OPEN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn state() -> Option<&'static mut State> {
    if !OPEN.load(Ordering::Acquire) {
        return None;
    }
    // SAFETY: written by `vnet_open` before OPEN; one thread uses it.
    Some(unsafe { (*STATE.0.get()).assume_init_mut() })
}

fn pool() -> &'static mut Pool {
    // SAFETY: zeroed is a valid empty pool; one thread uses it.
    unsafe { (*POOL.0.get()).assume_init_mut() }
}

/// The bytes of buffer `n`.
fn buffer(n: u32) -> Option<&'static mut [u8]> {
    let at = pool().at(n)?;
    // SAFETY: the buffer lies in an object the C library mapped read and
    // write for the process's life; the caller holds no other reference.
    Some(unsafe { core::slice::from_raw_parts_mut(at as *mut u8, BUFFER_LEN) })
}

/// Opens the device of `c`: the transport, the reset, the features as the
/// network service asks for them (MTU, MAC, STATUS), two queues, the queue
/// of receiving full. 0, or a negative code.
///
/// # Safety
///
/// `c` is a claim `stafeto_fast_claim` filled, and its mappings last.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vnet_open(c: *const Claim) -> c_int {
    // SAFETY: the caller's promise.
    let Some(c) = (unsafe { c.as_ref() }) else {
        return NO_OBJECTS;
    };
    let [queues, a, b, d, e] = c.objects;
    let region = |o: Object| Region {
        va: o.va as usize,
        pa: o.pa,
        len: o.pages as usize * PAGE,
    };
    let buffers = [region(a), region(b), region(d), region(e)];
    if buffers.iter().any(|r| r.len < PER_OBJECT * BUFFER_LEN)
        || !host::attach(0, region(queues), &buffers)
    {
        return NO_OBJECTS;
    }
    pool().fill(buffers.map(|r| r.va));
    let mut transport: SomeTransport<'static> = match c.kind {
        proto_net::fast::MMIO => {
            // SAFETY: the C library mapped the transport's page as device
            // memory, read and write, for the process's life.
            match unsafe { transport::mmio_transport(c.window as usize) } {
                Ok((t, _)) => t.into(),
                Err(_) => return NO_TRANSPORT,
            }
        }
        proto_net::fast::PCI => {
            let snapshot = Snapshot::new(c.snapshot, c.bar_sizes);
            let bar = Region {
                va: c.window as usize,
                pa: transport::bar0_address(&snapshot),
                len: c.window_len as usize,
            };
            match transport::pci_transport::<0, _>(snapshot, bar) {
                Ok((t, _)) => t.into(),
                Err(_) => return NO_TRANSPORT,
            }
        }
        _ => return NO_TRANSPORT,
    };
    match open::open(&mut transport, MTU | MAC | STATUS) {
        Ok(opened) if opened.mac == c.config.mac => {}
        _ => return REFUSED,
    }
    let Ok(rx) = Queue::new(&mut transport, RECEIVEQ, false, false) else {
        return NO_QUEUES;
    };
    let Ok(mut tx) = Queue::new(&mut transport, TRANSMITQ, false, false) else {
        return NO_QUEUES;
    };
    // No interrupt for sent buffers: `vnet_tx_reclaim` takes them back
    // (Virtio 1.2, 5.1.6.2.3).
    tx.set_dev_notify(false);
    // SAFETY: one thread; nothing refers to the state before OPEN.
    unsafe {
        (*STATE.0.get()).write(State {
            transport,
            rx,
            tx,
            rx_of: [NONE; QUEUE_SIZE],
            tx_of: [NONE; QUEUE_SIZE],
            rx_dirty: false,
            tx_dirty: false,
            ring: c.ring as usize,
        });
    }
    OPEN.store(true, Ordering::Release);
    let Some(s) = state() else {
        return NO_QUEUES;
    };
    refill(s);
    s.transport.finish_init();
    barrier::ring(&mut s.transport, RECEIVEQ);
    s.rx_dirty = false;
    0
}

/// The queue of receiving gets buffers of the pool until it is full
/// (Virtio 1.2, 5.1.6.3: a driver keeps it so).
fn refill(s: &mut State) {
    while s.rx.available_desc() > 0 {
        let Some(n) = pool().take() else {
            return;
        };
        let Some(slice) = buffer(n) else {
            return;
        };
        // SAFETY: the buffer is the pool's and untouched until popped.
        match unsafe { s.rx.add(&[], &mut [slice]) } {
            Ok(token) if usize::from(token) < QUEUE_SIZE => {
                s.rx_of[usize::from(token)] = n;
                s.rx_dirty = true;
            }
            _ => {
                pool().give(n);
                return;
            }
        }
    }
}

/// Up to `n` received frames into `out`: the count. The frames are the
/// program's until `vnet_rx_return`; the queue gets the pool's buffers
/// first.
///
/// # Safety
///
/// `out` has room for `n` values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vnet_rx_burst(out: *mut Buf, n: c_int) -> c_int {
    let Some(s) = state() else {
        return -1;
    };
    refill(s);
    if core::mem::take(&mut s.rx_dirty) && s.rx.should_notify() {
        barrier::ring(&mut s.transport, RECEIVEQ);
    }
    let mut got = 0;
    while got < n.max(0) && s.rx.can_pop() {
        // The device wrote the used index after the buffer.
        barrier::rmb();
        let Some(token) = s.rx.peek_used() else {
            break;
        };
        let Some(&b) = s.rx_of.get(usize::from(token)) else {
            return -1;
        };
        let Some(slice) = buffer(b) else {
            return -1;
        };
        // SAFETY: the buffer `refill` added with this token.
        let Ok(used) = (unsafe { s.rx.pop_used(token, &[], &mut [&mut *slice]) }) else {
            return -1;
        };
        s.rx_of[usize::from(token)] = NONE;
        match rx_frame(slice, used as usize) {
            Some(frame) => {
                // SAFETY: the caller's room for `n`.
                unsafe {
                    out.add(got as usize).write(Buf {
                        buf: b,
                        len: frame.len() as u32,
                        frame: frame.as_ptr() as *mut c_void,
                    })
                };
                got += 1;
            }
            None => pool().give(b),
        }
    }
    got
}

/// Buffer `buf` goes back to the pool.
#[unsafe(no_mangle)]
pub extern "C" fn vnet_rx_return(buf: u32) {
    pool().give(buf);
}

/// A buffer of the pool for a frame to send, or `VNET_NONE`.
#[unsafe(no_mangle)]
pub extern "C" fn vnet_buf_take() -> u32 {
    pool().take().unwrap_or(NONE)
}

/// How many buffers the pool holds free: the program's measure for how
/// many frames it may keep without a copy.
#[unsafe(no_mangle)]
pub extern "C" fn vnet_buf_free() -> u32 {
    pool().free_len as u32
}

/// Where the frame of buffer `buf` starts (after the Virtio header).
#[unsafe(no_mangle)]
pub extern "C" fn vnet_buf_ptr(buf: u32) -> *mut c_void {
    match pool().at(buf) {
        Some(at) => (at + HDR_LEN) as *mut c_void,
        None => core::ptr::null_mut(),
    }
}

/// The frame of `len` bytes in buffer `buf` into the queue of sending,
/// without the doorbell: 0, or -1 when the queue is full or the frame too
/// long (the buffer stays the program's).
#[unsafe(no_mangle)]
pub extern "C" fn vnet_tx(buf: u32, len: u16) -> c_int {
    let Some(s) = state() else {
        return -1;
    };
    let Some(slice) = buffer(buf) else {
        return -1;
    };
    let Some(total) = tx_prepare(slice, usize::from(len)) else {
        return -1;
    };
    let shared: &[u8] = &slice[..total];
    // SAFETY: the buffer is untouched until `vnet_tx_reclaim` pops it.
    match unsafe { s.tx.add(&[shared], &mut []) } {
        Ok(token) if usize::from(token) < QUEUE_SIZE => {
            s.tx_of[usize::from(token)] = buf;
            s.tx_dirty = true;
            0
        }
        _ => -1,
    }
}

/// The doorbell of the queue of sending, after its barrier, if frames went
/// in and the device asks for it.
#[unsafe(no_mangle)]
pub extern "C" fn vnet_tx_kick() {
    if let Some(s) = state()
        && core::mem::take(&mut s.tx_dirty)
        && s.tx.should_notify()
    {
        barrier::ring(&mut s.transport, TRANSMITQ);
    }
}

/// The buffers the device sent go back to the pool: how many.
#[unsafe(no_mangle)]
pub extern "C" fn vnet_tx_reclaim() -> c_int {
    let Some(s) = state() else {
        return -1;
    };
    let mut count = 0;
    while s.tx.can_pop() {
        barrier::rmb();
        let Some(token) = s.tx.peek_used() else {
            break;
        };
        let b = s.tx_of.get(usize::from(token)).copied().unwrap_or(NONE);
        let Some(slice) = buffer(b) else {
            return -1;
        };
        // SAFETY: the buffer `vnet_tx` added with this token; only the
        // number of descriptors of the chain matters to the crate.
        if unsafe { s.tx.pop_used(token, &[&slice[..HDR_LEN]], &mut []) }.is_err() {
            return -1;
        }
        s.tx_of[usize::from(token)] = NONE;
        pool().give(b);
        count += 1;
    }
    count
}

/// The device's interrupts for received frames on (1) or off (0). After
/// `on` the program looks at the queue once more (Virtio 1.2, 2.7.10): a
/// frame that came in between brings no interrupt.
#[unsafe(no_mangle)]
pub extern "C" fn vnet_notify(on: c_int) {
    if let Some(s) = state() {
        s.rx.set_dev_notify(on != 0);
        if on != 0 {
            // A full barrier between the flag and the next look at the used
            // index (Virtio 1.2, 2.7.10): the flag store is a release and
            // the look an acquire, which AArch64 may reorder past each
            // other without it.
            core::sync::atomic::fence(Ordering::SeqCst);
        }
    }
}

/// 1 when the device was reset under the program (its status lacks
/// DRIVER_OK): the network service ended and init stopped the device.
#[unsafe(no_mangle)]
pub extern "C" fn vnet_lost() -> c_int {
    match state() {
        Some(s) => c_int::from(!s.transport.get_status().contains(DeviceStatus::DRIVER_OK)),
        None => 1,
    }
}

/// The IPv4 header sum and the TCP or UDP sum of a frame of the wire.
///
/// # Safety
///
/// `frame` has `len` bytes, read and write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vnet_fill_sums(frame: *mut c_void, len: usize) {
    if frame.is_null() || len > MAX_FRAME {
        return;
    }
    // SAFETY: the caller's promise.
    fill_sums(unsafe { core::slice::from_raw_parts_mut(frame.cast::<u8>(), len) });
}

fn ring_word(base: usize, offset: usize) -> &'static AtomicU32 {
    // SAFETY: page 0 of the ring the C library mapped, aligned to 4.
    unsafe { &*((base + offset) as *const AtomicU32) }
}

fn ring_len(base: usize, ring: usize, slot: u32) -> &'static AtomicU16 {
    // SAFETY: as `ring_word`, aligned to 2.
    unsafe { &*((base + len_offset(ring, slot)) as *const AtomicU16) }
}

/// The frame into the bypass ring to the network service (a server's DHCP
/// message to the second address, or an ARP reply for it; the service
/// checks it again): 1, or 0 when the ring is full. `stafeto_fast_kick`
/// tells the service.
///
/// # Safety
///
/// `frame` has `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vnet_bypass_push(frame: *const c_void, len: usize) -> c_int {
    let Some(s) = state() else {
        return 0;
    };
    if frame.is_null() || len == 0 || len > FRAME_MAX {
        return 0;
    }
    let head = ring_word(s.ring, head_offset(TO_SERVICE)).load(Ordering::Relaxed);
    let tail = ring_word(s.ring, tail_offset(TO_SERVICE)).load(Ordering::Acquire);
    if head.wrapping_sub(tail) >= RING_SLOTS {
        return 0;
    }
    let to = (s.ring + slot_offset(TO_SERVICE, head)) as *mut u8;
    // SAFETY: the slot lies in the ring, the frame fits it, and the service
    // reads it only after the head moves.
    unsafe { core::ptr::copy_nonoverlapping(frame.cast::<u8>(), to, len) };
    ring_len(s.ring, TO_SERVICE, head).store(len as u16, Ordering::Relaxed);
    ring_word(s.ring, head_offset(TO_SERVICE)).store(head.wrapping_add(1), Ordering::Release);
    1
}

/// The next frame the service put in the ring to the program, into
/// `frame`: its length, or 0 when there is none (or `cap` is too small, and
/// the frame is dropped).
///
/// # Safety
///
/// `frame` has room for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vnet_bypass_pop(frame: *mut c_void, cap: usize) -> usize {
    let Some(s) = state() else {
        return 0;
    };
    let head = ring_word(s.ring, head_offset(TO_OWNER)).load(Ordering::Acquire);
    let tail = ring_word(s.ring, tail_offset(TO_OWNER)).load(Ordering::Relaxed);
    let waiting = head.wrapping_sub(tail);
    if waiting == 0 || waiting > RING_SLOTS {
        return 0;
    }
    let len = usize::from(ring_len(s.ring, TO_OWNER, tail).load(Ordering::Relaxed));
    let fits = len > 0 && len <= FRAME_MAX && len <= cap && !frame.is_null();
    if fits {
        let from = (s.ring + slot_offset(TO_OWNER, tail)) as *const u8;
        // SAFETY: the slot lies in the ring; the caller's room.
        unsafe { core::ptr::copy_nonoverlapping(from, frame.cast::<u8>(), len) };
    }
    ring_word(s.ring, tail_offset(TO_OWNER)).store(tail.wrapping_add(1), Ordering::Release);
    if fits { len } else { 0 }
}

#[cfg(all(feature = "ffi", target_os = "none"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe extern "C" {
        fn abort() -> !;
    }
    // SAFETY: the C library's abort ends the process.
    unsafe { abort() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_buffer_lies_in_its_own_object() {
        let mut pool = Pool {
            bases: [0; 4],
            free: [0; BUFFERS],
            free_len: 0,
        };
        let bases = [
            0x20_0000_0000,
            0x20_0040_0000,
            0x20_0100_0000,
            0x20_00c0_0000,
        ];
        pool.fill(bases);
        assert_eq!(pool.at(0), Some(bases[0]));
        assert_eq!(pool.at(2047), Some(bases[0] + 2047 * 2048));
        assert_eq!(pool.at(2048), Some(bases[1]));
        assert_eq!(pool.at(3 * 2048 + 5), Some(bases[3] + 5 * 2048));
        assert_eq!(pool.at(BUFFERS as u32), None);
        assert_eq!(pool.at(NONE), None);
        // The pool hands out every buffer once, the four objects in turn.
        let first: Vec<u32> = (0..4).map(|_| pool.take().unwrap()).collect();
        assert_eq!(first, [0, 2048, 4096, 6144]);
        assert_eq!(pool.free_len, BUFFERS - 4);
        for n in first.into_iter().rev() {
            pool.give(n);
        }
        let mut seen = vec![false; BUFFERS];
        while let Some(n) = pool.take() {
            assert!(!seen[n as usize]);
            seen[n as usize] = true;
        }
        assert!(seen.iter().all(|&s| s));
        pool.give(7);
        pool.give(BUFFERS as u32);
        assert_eq!(pool.take(), Some(7));
        assert_eq!(pool.take(), None);
    }
}
