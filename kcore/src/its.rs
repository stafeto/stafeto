// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The GICv3 ITS and LPIs (spec 9, [G40]-[G48]): register layout, the
//! 32-byte commands of the command queue, the sizes of the tables the
//! kernel gives the ITS, and the map of the LPI numbers it hands out.
//! Pure arithmetic; the driver that writes the registers and the queue
//! lives in the kernel.

use crate::gic::FIRST_LPI;

// Registers of the ITS control frame [G43].
pub const GITS_CTLR: usize = 0x000;
pub const GITS_TYPER: usize = 0x008;
pub const GITS_CBASER: usize = 0x080;
pub const GITS_CWRITER: usize = 0x088;
pub const GITS_CREADR: usize = 0x090;
pub const GITS_BASER: usize = 0x100;
/// The translation frame follows the control frame, and GITS_TRANSLATER is
/// at +0x40 in it: the address a device writes the EventID to.
pub const TRANSLATION_FRAME: u64 = 0x1_0000;
pub const GITS_TRANSLATER: u64 = TRANSLATION_FRAME + 0x40;
/// The GITS_BASER registers there are.
pub const BASER_COUNT: usize = 8;

/// GITS_CTLR.Enabled and .Quiescent.
pub const CTLR_ENABLED: u32 = 1;
pub const CTLR_QUIESCENT: u32 = 1 << 31;

// Registers of the redistributor's RD_base frame [G41].
pub const GICR_PROPBASER: usize = 0x070;
pub const GICR_PENDBASER: usize = 0x078;
/// GICR_CTLR.EnableLPIs.
pub const GICR_CTLR_ENABLE_LPIS: u32 = 1;
/// GICR_TYPER.PLPIS, Processor_Number [23:8].
pub const GICR_TYPER_PLPIS: u64 = 1;
pub const fn processor_number(typer: u64) -> u64 {
    (typer >> 8) & 0xFFFF
}

/// The INTID bits the kernel gives the redistributors: 14, INTIDs below
/// 16384 [G42].
pub const ID_BITS: u32 = 14;
/// The first INTID past the LPIs the redistributors cover.
pub const LPI_END: u32 = 1 << ID_BITS;
/// The LPIs the kernel hands out, INTID 8192 on (spec 7.8).
pub const MAX_LPIS: usize = 1024;
/// The property table: a byte for each LPI of the range, from INTID 8192
/// [G42]. Bit 0 enables the LPI, bit 1 is RES1 (Group 1).
pub const PROP_TABLE_BYTES: usize = (LPI_END - FIRST_LPI) as usize;
pub const PROP_ENABLE: u8 = 1;
pub const PROP_GROUP1: u8 = 2;
/// The pending table of a redistributor: a bit for each INTID below
/// LPI_END, aligned to 64 KiB [G42].
pub const PEND_TABLE_BYTES: usize = (LPI_END / 8) as usize;
pub const PEND_ALIGN: usize = 0x1_0000;
/// The index of an LPI's byte in the property table.
pub const fn prop_index(intid: u32) -> usize {
    (intid - FIRST_LPI) as usize
}
/// The property byte of an enabled LPI of `priority` (the low bits of the
/// priority byte are the flags).
pub const fn prop_byte(priority: u8) -> u8 {
    (priority & 0xFC) | PROP_GROUP1 | PROP_ENABLE
}

/// Cacheability field values of the *BASER registers [G41].
pub const CACHE_NC: u64 = 1;
pub const CACHE_RAWAWB: u64 = 7;
/// Shareability field values: non-shareable, inner shareable.
pub const SHARE_NON: u64 = 0;
pub const SHARE_INNER: u64 = 1;

/// GICR_PROPBASER [G41]: the table at `pa` (4 KiB aligned), IDbits - 1 in
/// the low field.
pub const fn propbaser(pa: u64, id_bits: u32, share: u64, cache: u64) -> u64 {
    (pa & 0x000F_FFFF_FFFF_F000) | (cache << 7) | (share << 10) | (id_bits as u64 - 1)
}

/// GICR_PENDBASER [G41]: the table at `pa` (64 KiB aligned), PTZ set
/// (the table is zero).
pub const fn pendbaser(pa: u64, share: u64, cache: u64) -> u64 {
    (pa & 0x000F_FFFF_FFFF_0000) | (cache << 7) | (share << 10) | (1 << 62)
}

/// GITS_CBASER [G44]: `pages` pages of 4 KiB at `pa`, valid.
pub const fn cbaser(pa: u64, pages: u32, share: u64, cache: u64) -> u64 {
    (pa & 0x000F_FFFF_FFFF_F000) | (cache << 59) | (share << 10) | (pages as u64 - 1) | (1 << 63)
}

/// The GITS_BASER fields the kernel reads [G45].
pub const BASER_TYPE_DEVICE: u64 = 1;
pub const BASER_TYPE_COLLECTION: u64 = 4;
pub const fn baser_type(baser: u64) -> u64 {
    (baser >> 56) & 7
}
pub const fn baser_entry_size(baser: u64) -> u64 {
    ((baser >> 48) & 0x1F) + 1
}
/// The page size the register holds, in bytes: 4 KiB, 16 KiB, 64 KiB.
pub const fn baser_page_size(baser: u64) -> u64 {
    match (baser >> 8) & 3 {
        0 => 0x1000,
        1 => 0x4000,
        _ => 0x1_0000,
    }
}
/// The Page_Size field [9:8] for `page` bytes (4, 16 or 64 KiB) [G45, G49].
pub const fn baser_page_code(page: u64) -> u64 {
    match page {
        0x1000 => 0,
        0x4000 => 1,
        _ => 2,
    }
}
/// The page sizes the kernel tries, in order [G49].
pub const BASER_PAGES: [u64; 3] = [0x1000, 0x4000, 0x1_0000];
/// The value written to find out whether the register holds `page`: the
/// type and entry size it read, the page size, no table, not valid.
pub const fn baser_probe(old: u64, page: u64) -> u64 {
    (old & (0x1F << 48 | 7 << 56)) | (baser_page_code(page) << 8)
}
/// The first of the sizes in `BASER_PAGES` from `first` on that the
/// register read back as written; `hold` writes the probe and reads. None:
/// the ITS takes no page size.
pub fn pick_page(old: u64, first: u64, mut hold: impl FnMut(u64) -> u64) -> Option<u64> {
    BASER_PAGES.into_iter().filter(|p| *p >= first).find(|p| {
        let probe = baser_probe(old, *p);
        (hold(probe) >> 8) & 3 == baser_page_code(*p)
    })
}
/// The address field of a GITS_BASER for a table at `pa` aligned to `page`:
/// PA[47:12] for 4 and 16 KiB, and for 64 KiB PA[47:16] in [47:16] and
/// PA[51:48] in [15:12] [G45, G49].
pub const fn baser_address(pa: u64, page: u64) -> u64 {
    if page == 0x1_0000 {
        (pa & 0x0000_FFFF_FFFF_0000) | (((pa >> 48) & 0xF) << 12)
    } else {
        pa & 0x0000_FFFF_FFFF_F000
    }
}
/// A GITS_BASER value for a flat table of `pages` pages of `page` bytes at
/// `pa`, of the type and entry size `old` read back, valid [G45]. Size
/// counts pages of `page`.
pub const fn baser(old: u64, pa: u64, pages: u32, page: u64, share: u64, cache: u64) -> u64 {
    (old & (0x1F << 48 | 7 << 56))
        | baser_address(pa, page)
        | (baser_page_code(page) << 8)
        | (cache << 59)
        | (share << 10)
        | (pages as u64 - 1)
        | (1 << 63)
}
/// What a boot-time table needs: how many entries it holds, in how many
/// pages of the ITS, and the bytes the allocator gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Table {
    pub entries: u32,
    pub pages: u32,
    pub bytes: usize,
}
/// The largest flat device table.
pub const DEVICE_TABLE_MAX: u64 = 0x1_0000;
/// The device table: DeviceIDs up to `max_device_id`, cut to what
/// `device_bits` bits and `DEVICE_TABLE_MAX` bytes hold, in pages of `page`.
pub fn device_table(max_device_id: u32, entry: u64, device_bits: u32, page: u64) -> Table {
    let by_bits = 1u64 << device_bits.min(32);
    let entries = (u64::from(max_device_id) + 1)
        .min(by_bits)
        .min(DEVICE_TABLE_MAX / entry);
    let pages = (entries * entry).div_ceil(page) as u32;
    Table {
        entries: entries as u32,
        pages,
        bytes: pages as usize * page as usize,
    }
}
/// The collection table for `cpus` collections, in pages of `page`.
pub fn collection_table(cpus: usize, entry: u64, page: u64) -> Table {
    let pages = (cpus as u64 * entry).div_ceil(page).max(1) as u32;
    Table {
        entries: cpus as u32,
        pages,
        bytes: pages as usize * page as usize,
    }
}
/// The order of the allocator block for `bytes`, in frames of 4 KiB.
pub const fn block_order(bytes: usize) -> u8 {
    (bytes.div_ceil(0x1000).next_power_of_two()).trailing_zeros() as u8
}

/// GICD_TYPER's LPI fields [G50]: LPIS [17], IDbits [23:19] (plus one),
/// num_LPIs [15:11].
pub const fn gicd_lpis(typer: u32) -> bool {
    typer & (1 << 17) != 0
}
pub const fn gicd_id_bits(typer: u32) -> u32 {
    ((typer >> 19) & 0x1F) + 1
}
/// The LPIs the distributor gives, from INTID 8192: 2^(num_LPIs + 1) when
/// the field is not 0, else None (the range IDbits give).
pub const fn gicd_num_lpis(typer: u32) -> Option<u32> {
    let n = (typer >> 11) & 0x1F;
    if n == 0 {
        None
    } else if n >= 31 {
        Some(u32::MAX)
    } else {
        Some(1 << (n + 1))
    }
}
/// The LPIs the kernel hands out on a distributor with `typer` in
/// GICD_TYPER: MAX_LPIS, or fewer when the distributor restricts the range
/// (`num_LPIs`, 128 on a t4g) [G50].
pub const fn lpi_limit(typer: u32) -> u32 {
    match gicd_num_lpis(typer) {
        Some(n) if n < MAX_LPIS as u32 => n,
        _ => MAX_LPIS as u32,
    }
}

/// Whether the registers hold the shareability and cacheability written:
/// Shareability [11:10] not 0 and Inner Cache [9:7] not 0 or 1 [G51].
pub const fn holds_shareability(read: u64) -> bool {
    (read >> 10) & 3 != 0 && (read >> 7) & 7 > 1
}

/// GITS_TYPER fields [G43].
pub const fn typer_itt_entry_size(typer: u64) -> u64 {
    ((typer >> 4) & 0xF) + 1
}
pub const fn typer_device_bits(typer: u64) -> u32 {
    (((typer >> 13) & 0x1F) + 1) as u32
}
pub const fn typer_event_bits(typer: u64) -> u32 {
    (((typer >> 8) & 0x1F) + 1) as u32
}
/// PTA: the target of a collection is a physical address.
pub const fn typer_pta(typer: u64) -> bool {
    typer & (1 << 19) != 0
}
/// HCC, the collections the ITS keeps without a table.
pub const fn typer_hcc(typer: u64) -> u64 {
    (typer >> 24) & 0xFF
}

/// The pages of 4 KiB a flat device table needs for DeviceIDs up to
/// `max_device_id`, of `entry_size`-byte entries; None past `limit_pages`.
pub fn device_table_pages(max_device_id: u32, entry_size: u64, limit_pages: u32) -> Option<u32> {
    let bytes = (u64::from(max_device_id) + 1) * entry_size;
    let pages = u32::try_from(bytes.div_ceil(0x1000)).ok()?;
    (pages <= limit_pages).then_some(pages)
}

/// The pages of a collection table for `cpus` collections.
pub fn collection_table_pages(cpus: usize, entry_size: u64) -> u32 {
    (cpus as u64 * entry_size).div_ceil(0x1000).max(1) as u32
}

/// The most events a device of `msi_create` has (spec 9).
pub const MAX_MSI_EVENTS: u64 = 64;
/// The largest ITT of a device: 64 events of an entry up to 16 bytes.
pub const ITT_MAX_BYTES: usize = 1024;
pub const ITT_ALIGN: usize = 256;

/// The EventID bits of a device with `events` events: its ITT has
/// 2^bits entries, at least 2 (a MAPD Size field holds bits - 1 [G46]).
pub const fn event_bits(events: u64) -> u32 {
    let events = if events < 2 { 2 } else { events };
    64 - (events - 1).leading_zeros()
}

/// The bytes of an ITT for `events` events of `entry_size`-byte entries
/// [G47]; None when it would not fit ITT_MAX_BYTES.
pub fn itt_bytes(events: u64, entry_size: u64) -> Option<usize> {
    let bytes = (1usize << event_bits(events)).checked_mul(entry_size as usize)?;
    (bytes <= ITT_MAX_BYTES).then_some(bytes)
}

// The commands [G46].
pub const CMD_INT: u64 = 0x03;
pub const CMD_SYNC: u64 = 0x05;
pub const CMD_MAPD: u64 = 0x08;
pub const CMD_MAPC: u64 = 0x09;
pub const CMD_MAPTI: u64 = 0x0A;
pub const CMD_INV: u64 = 0x0C;
pub const CMD_INVALL: u64 = 0x0D;
pub const CMD_DISCARD: u64 = 0x0F;

/// A command of the queue, four doublewords.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Command(pub [u64; 4]);

/// Bytes a command takes in the queue.
pub const COMMAND_BYTES: usize = 32;
/// The queue is one page.
pub const QUEUE_BYTES: usize = 4096;
pub const QUEUE_SLOTS: usize = QUEUE_BYTES / COMMAND_BYTES;
/// The commands one call of the kernel puts in the queue before it waits
/// for them (spec 8.1).
pub const MAX_BATCH: usize = 4;

impl Command {
    /// The name of the command in a panic message.
    pub fn name(&self) -> &'static str {
        match self.0[0] & 0xFF {
            CMD_INT => "INT",
            CMD_SYNC => "SYNC",
            CMD_MAPD => "MAPD",
            CMD_MAPC => "MAPC",
            CMD_MAPTI => "MAPTI",
            CMD_INV => "INV",
            CMD_INVALL => "INVALL",
            CMD_DISCARD => "DISCARD",
            _ => "an unknown command",
        }
    }

    fn with_device(op: u64, device_id: u32) -> Command {
        Command([op | (u64::from(device_id) << 32), 0, 0, 0])
    }

    /// MAPD: DeviceID `device_id` gets the ITT at `itt` (256-byte aligned)
    /// of 2^`event_bits` entries; `valid` false unmaps it.
    pub fn mapd(device_id: u32, itt: u64, event_bits: u32, valid: bool) -> Command {
        let mut c = Self::with_device(CMD_MAPD, device_id);
        c.0[1] = u64::from(event_bits - 1) & 0x1F;
        c.0[2] = (itt & 0x000F_FFFF_FFFF_FF00) | (u64::from(valid) << 63);
        c
    }

    /// MAPC: collection `icid` goes to the redistributor `rdbase` (a
    /// processor number << 16, or a physical address with PTA).
    pub fn mapc(icid: u16, rdbase: u64, valid: bool) -> Command {
        Command([
            CMD_MAPC,
            0,
            (rdbase & 0x000F_FFFF_FFFF_0000) | u64::from(icid) | (u64::from(valid) << 63),
            0,
        ])
    }

    /// MAPTI: (`device_id`, `event_id`) becomes LPI `intid` in collection
    /// `icid`.
    pub fn mapti(device_id: u32, event_id: u32, intid: u32, icid: u16) -> Command {
        let mut c = Self::with_device(CMD_MAPTI, device_id);
        c.0[1] = u64::from(event_id) | (u64::from(intid) << 32);
        c.0[2] = u64::from(icid);
        c
    }

    fn with_event(op: u64, device_id: u32, event_id: u32) -> Command {
        let mut c = Self::with_device(op, device_id);
        c.0[1] = u64::from(event_id);
        c
    }

    /// INV: the redistributor rereads the property byte of the event's LPI.
    pub fn inv(device_id: u32, event_id: u32) -> Command {
        Self::with_event(CMD_INV, device_id, event_id)
    }

    /// DISCARD: drops the mapping of the event and clears its pending LPI.
    pub fn discard(device_id: u32, event_id: u32) -> Command {
        Self::with_event(CMD_DISCARD, device_id, event_id)
    }

    /// INT: the ITS acts as if the device had written the event.
    pub fn int(device_id: u32, event_id: u32) -> Command {
        Self::with_event(CMD_INT, device_id, event_id)
    }

    /// SYNC: completes the commands before it for the redistributor
    /// `rdbase`.
    pub fn sync(rdbase: u64) -> Command {
        Command([CMD_SYNC, 0, rdbase & 0x000F_FFFF_FFFF_0000, 0])
    }

    /// INVALL: the redistributor rereads every LPI of collection `icid`.
    pub fn invall(icid: u16) -> Command {
        Command([CMD_INVALL, 0, u64::from(icid), 0])
    }
}

/// The slots of the queue free for the writer at byte offset `cwriter`
/// when the ITS has read up to `creadr` (both multiples of 32 below
/// QUEUE_BYTES): one slot stays empty, so that a full queue differs from
/// an empty one.
pub const fn free_slots(creadr: usize, cwriter: usize) -> usize {
    (creadr + QUEUE_BYTES - cwriter - COMMAND_BYTES) % QUEUE_BYTES / COMMAND_BYTES
}

/// The offset after `at` in the queue, wrapping.
pub const fn next_offset(at: usize) -> usize {
    (at + COMMAND_BYTES) % QUEUE_BYTES
}

/// The commands the ITS has still to read when the writer is at `cwriter`
/// and the reader at `creadr`.
pub const fn pending(creadr: usize, cwriter: usize) -> usize {
    (cwriter + QUEUE_BYTES - creadr) % QUEUE_BYTES / COMMAND_BYTES
}

/// The slots of the queue a sender that holds `OBJ` may fill and no other
/// sender may: a section reserves its commands (`room`) before it changes
/// anything, and the commands go in later, so what a sender outside `OBJ`
/// takes in between must leave them (spec 8.1).
pub const QUEUE_KEEP: usize = MAX_BATCH;

/// The byte offset the writer is at after `sent` commands in all: the
/// queue starts empty at offset 0, so the count of commands sent and the
/// offset are one number (spec 8.1).
pub const fn write_offset(sent: u64) -> usize {
    (sent % QUEUE_SLOTS as u64) as usize * COMMAND_BYTES
}

/// The commands the ITS has run of the `sent` ones in all, when it has
/// read up to `creadr`: sent less those it still has to read. `sent` is
/// 64 bits wide and never wraps in the life of the machine, so a target
/// taken from it compares with the answer at any distance, which a
/// position on the ring cannot do once other CPUs have sent a lap's worth
/// of commands meanwhile.
pub fn done(sent: u64, creadr: usize) -> u64 {
    #[cfg(feature = "break-its-counter-32")]
    let sent = sent & 0xFFFF_FFFF;
    sent - pending(creadr, write_offset(sent)) as u64
}

/// True once the ITS has run the first `target` commands.
pub fn reached(sent: u64, creadr: usize, target: u64) -> bool {
    if cfg!(feature = "break-its-ring-position") {
        return pending(creadr, write_offset(target)) == 0;
    }
    done(sent, creadr) >= target
}

/// Whether `need` commands go into the queue now and leave `keep` slots
/// free, when `sent` commands went in and the ITS is known to have run
/// `done` of them (a count that only lags the truth, so the answer only
/// under-counts the room): a section asks with `keep` 0, a sender outside
/// `OBJ` with QUEUE_KEEP.
pub fn room(sent: u64, done: u64, need: usize, keep: usize) -> bool {
    #[cfg(feature = "break-its-keep")]
    let keep = {
        let _ = keep;
        0
    };
    let outstanding = sent.saturating_sub(done) as usize;
    (QUEUE_SLOTS - 1).saturating_sub(outstanding) >= need + keep
}

/// Whether the ITS has stopped (spec 8.1): commands are outstanding and
/// `done` has not moved, and nothing has been sent, for `limit` ticks. The
/// clock is the machine's: the last time `done` advanced (`last_advance`)
/// and the last time commands went in (`last_send`), whichever is later.
/// The time a portion of cleanup has waited for its turn is no evidence of
/// a stop, since the ITS runs on its own.
pub fn stalled(now: u64, last_advance: u64, last_send: u64, limit: u64) -> bool {
    #[cfg(feature = "break-its-stall-clock")]
    let last_advance = {
        let _ = last_advance;
        0
    };
    now.saturating_sub(last_advance.max(last_send)) > limit
}

/// What a portion of cleanup waits for before its section: the commands
/// of its object's teardown, which it sent in one portion and finds run in
/// a later one (spec 7.7, 8.1). The object keeps it. `target` is the count
/// of commands sent when its commands went in; 0 before they did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Wait {
    target: u64,
}

/// What one step of a `Wait` found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The commands ran: the portion goes on to its section.
    Done,
    /// They did not, or the queue had no room for them, or no consistent
    /// look at the queue was had: the portion queues its object again and
    /// returns.
    Again,
    /// The ITS has not moved for the limit with commands outstanding.
    Stalled,
}

impl Wait {
    pub const fn new() -> Wait {
        Wait { target: 0 }
    }

    /// One step. `send` puts the commands in and gives the count of commands
    /// sent after them, or None when the queue has no room; it is called
    /// until it gives one and not again. `done` gives the commands the ITS
    /// has run so far, read once, or None when no consistent look was had
    /// (another CPU was adding commands), which is "not yet". `stalled` is
    /// asked only when the commands have not run.
    pub fn step(
        &mut self,
        send: impl FnOnce() -> Option<u64>,
        done: impl FnOnce() -> Option<u64>,
        stalled: impl FnOnce() -> bool,
    ) -> Step {
        let mut sent_now = false;
        if self.target == 0 || cfg!(feature = "break-its-step-resend") {
            match send() {
                Some(target) => {
                    self.target = target;
                    sent_now = true;
                }
                None => return Self::late(stalled),
            }
        }
        if cfg!(feature = "break-its-step-early") && sent_now {
            return Step::Done;
        }
        if done().is_some_and(|d| d >= self.target) {
            Step::Done
        } else {
            Self::late(stalled)
        }
    }

    fn late(stalled: impl FnOnce() -> bool) -> Step {
        if stalled() {
            Step::Stalled
        } else {
            Step::Again
        }
    }
}

/// GITS_CREADR and CWRITER hold the byte offset in bits [19:5] [G44].
pub const OFFSET_MASK: u64 = 0xF_FFE0;

/// The LPI numbers of the kernel: a bit for each of MAX_LPIS, set when the
/// LPI is taken. O(MAX_LPIS / 64) to take one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LpiMap {
    taken: [u64; MAX_LPIS / 64],
}

impl LpiMap {
    pub const fn new() -> LpiMap {
        LpiMap {
            taken: [0; MAX_LPIS / 64],
        }
    }

    /// The lowest free LPI, taken; None when all MAX_LPIS are in use.
    pub fn take(&mut self) -> Option<u32> {
        self.take_within(MAX_LPIS as u32)
    }

    /// The lowest free LPI below `limit` LPIs from INTID 8192, taken; None
    /// when they are all in use. The limit is what the distributor gives
    /// (`lpi_limit`).
    pub fn take_within(&mut self, limit: u32) -> Option<u32> {
        for (i, word) in self.taken.iter_mut().enumerate() {
            if *word != u64::MAX {
                let bit = (!*word).trailing_zeros();
                let n = (i as u32) * 64 + bit;
                if n >= limit {
                    return None;
                }
                *word |= 1 << bit;
                return Some(FIRST_LPI + n);
            }
        }
        None
    }

    /// Gives `intid` back.
    pub fn give(&mut self, intid: u32) {
        let n = intid - FIRST_LPI;
        assert!((n as usize) < MAX_LPIS, "not an LPI of the kernel");
        let (i, bit) = ((n / 64) as usize, n % 64);
        assert!(self.taken[i] & 1 << bit != 0, "an LPI given back twice");
        self.taken[i] &= !(1 << bit);
    }

    pub fn in_use(&self) -> usize {
        self.taken.iter().map(|w| w.count_ones() as usize).sum()
    }
}

impl Default for LpiMap {
    fn default() -> Self {
        Self::new()
    }
}

// The tables of the ITS on 64 KiB blocks, the read-back of every register
// and the self-test of the delivery (decision 2026-11-13, tasks/
// 2026-11-13-its-lpi-lost.md).

/// The granule a virtual ITS reads the addresses of the command queue and
/// the property table with: 64 KiB, as Linux allocates them.
pub const TABLE_ALIGN: u64 = 0x1_0000;

/// Whether a table at `pa` starts on a `TABLE_ALIGN` boundary.
pub const fn table_aligned(pa: u64) -> bool {
    pa.is_multiple_of(TABLE_ALIGN)
}

/// The allocator order of the command queue and of the property table: 16
/// frames of 4 KiB each, so that the blocks lie on 64 KiB. The break
/// `break-its-align-4k` returns to the 4 KiB and 8 KiB blocks of before.
pub const QUEUE_ORDER: u8 = if cfg!(feature = "break-its-align-4k") {
    0
} else {
    4
};
pub const PROP_ORDER: u8 = if cfg!(feature = "break-its-align-4k") {
    1
} else {
    4
};

const ADDR_4K: u64 = 0x000F_FFFF_FFFF_F000;
const ADDR_64K: u64 = 0x000F_FFFF_FFFF_0000;
/// The bits of GITS_CBASER that must read as written: Valid, the address
/// and Size.
pub const CBASER_CHECK: u64 = (1 << 63) | ADDR_4K | 0xFF;
/// The bits of GICR_PROPBASER that must read as written: the address and IDbits.
pub const PROPBASER_CHECK: u64 = ADDR_4K | 0x1F;
/// The bits of GICR_PENDBASER that must read as written: the address (PTZ
/// reads as 0).
pub const PENDBASER_CHECK: u64 = ADDR_64K;
/// The bits of a GITS_BASER that must read as written: Page_Size, Size,
/// Valid and the address field for pages of `page` bytes. The break
/// `break-its-readback-mask` keeps the mask of before, with no address.
pub const fn baser_check(page: u64) -> u64 {
    let base = (3 << 8) | 0xFF | (1 << 63);
    if cfg!(feature = "break-its-readback-mask") {
        base
    } else {
        base | baser_address(0x000F_FFFF_FFFF_FFFF, page)
    }
}

/// A register that did not read back as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadBack {
    pub reg: &'static str,
    pub wrote: u64,
    pub read: u64,
}

impl core::fmt::Display for ReadBack {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} reads back {:#x} (wrote {:#x})",
            self.reg, self.read, self.wrote
        )
    }
}

/// Ok when the bits of `mask` read as written.
pub fn verify(reg: &'static str, wrote: u64, read: u64, mask: u64) -> Result<(), ReadBack> {
    if (wrote ^ read) & mask == 0 {
        Ok(())
    } else {
        Err(ReadBack { reg, wrote, read })
    }
}

/// The physical addresses of the tables, for the line `its tables`.
pub struct Tables<'a> {
    pub queue: u64,
    pub prop: u64,
    pub pend: &'a [u64],
    pub dt: u64,
    pub ct: u64,
}

/// The address a line shows: the physical one. The break
/// `break-its-print-pa` shows the kernel's virtual address.
fn shown(pa: u64) -> u64 {
    if cfg!(feature = "break-its-print-pa") {
        crate::layout::LINEAR_BASE as u64 + pa
    } else {
        pa
    }
}

impl core::fmt::Display for Tables<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "its tables queue {:#x} prop {:#x}",
            shown(self.queue),
            shown(self.prop)
        )?;
        for (n, pa) in self.pend.iter().enumerate() {
            write!(f, " pend{n} {:#x}", shown(*pa))?;
        }
        write!(f, " dt {:#x} ct {:#x}", shown(self.dt), shown(self.ct))
    }
}

/// An LPI of the boot self-test that did not arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotDelivered {
    pub cpu: usize,
    pub lpi: u32,
}

impl core::fmt::Display for NotDelivered {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "LPI {} did not reach CPU {}", self.lpi, self.cpu)
    }
}

/// The verdict of the self-test: `arrived[c]` is the ticks the LPI of CPU
/// `c` (FIRST_LPI + c) took, None when it did not arrive in time.
pub fn verdict(arrived: &[Option<u64>]) -> Result<(), NotDelivered> {
    for (cpu, ticks) in arrived.iter().enumerate() {
        if ticks.is_none() {
            return Err(NotDelivered {
                cpu,
                lpi: FIRST_LPI + cpu as u32,
            });
        }
    }
    Ok(())
}

/// Clears EnableLPIs at entry, as Linux does for a kernel that finds it set:
/// write the register without the bit, wait for Register Write Pending
/// (`settle`, bounded by its caller), read again. Err(ctlr) when the bit is
/// still set, which leaves the tables of the firmware in use.
pub fn clear_enable_lpis(
    mut read: impl FnMut() -> u32,
    mut write: impl FnMut(u32),
    mut settle: impl FnMut(),
) -> Result<(), u32> {
    let ctlr = read();
    if ctlr & GICR_CTLR_ENABLE_LPIS == 0 {
        return Ok(());
    }
    write(ctlr & !GICR_CTLR_ENABLE_LPIS);
    settle();
    let after = read();
    if after & GICR_CTLR_ENABLE_LPIS == 0 {
        Ok(())
    } else {
        Err(after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translater_is_in_the_translation_frame() {
        assert_eq!(GITS_TRANSLATER, 0x1_0040);
    }

    #[test]
    fn table_sizes_follow_the_id_bits() {
        assert_eq!(PROP_TABLE_BYTES, 8192);
        assert_eq!(PEND_TABLE_BYTES, 2048);
        assert_eq!(prop_index(FIRST_LPI), 0);
        assert_eq!(prop_index(LPI_END - 1), PROP_TABLE_BYTES - 1);
    }

    #[test]
    fn property_byte_enables_group_1() {
        assert_eq!(prop_byte(0xA0), 0xA3);
        assert_eq!(prop_byte(0xA3), 0xA3);
    }

    #[test]
    fn redistributor_bases_take_the_fields_of_g41() {
        let p = propbaser(0x4800_0000, ID_BITS, SHARE_INNER, CACHE_RAWAWB);
        assert_eq!(p & 0x1F, 13);
        assert_eq!((p >> 7) & 7, 7);
        assert_eq!((p >> 10) & 3, 1);
        assert_eq!(p & !0xFFF & 0x000F_FFFF_FFFF_F000, 0x4800_0000);
        let q = pendbaser(0x4801_0000, SHARE_NON, CACHE_NC);
        assert_eq!(q >> 62 & 1, 1);
        assert_eq!(q & 0x000F_FFFF_FFFF_0000, 0x4801_0000);
        assert_eq!((q >> 7) & 7, 1);
    }

    #[test]
    fn queue_and_table_registers() {
        let c = cbaser(0x4802_0000, 1, SHARE_INNER, CACHE_RAWAWB);
        assert_eq!(c & 0xFF, 0);
        assert_eq!(c >> 63, 1);
        assert_eq!((c >> 59) & 7, 7);
        let old = (BASER_TYPE_DEVICE << 56) | (7 << 48) | (2 << 8);
        let b = baser(old, 0x4803_0000, 2, 0x1000, SHARE_INNER, CACHE_RAWAWB);
        assert_eq!(baser_type(b), BASER_TYPE_DEVICE);
        assert_eq!(baser_entry_size(b), 8);
        assert_eq!(b & 0xFF, 1);
        assert_eq!(b >> 63, 1);
        assert_eq!(baser_page_size(b), 0x1000);
        assert_eq!(baser_page_size(old), 0x1_0000);
    }

    #[test]
    fn the_page_size_is_the_first_the_register_reads_back() {
        let old = (BASER_TYPE_DEVICE << 56) | (7 << 48);
        assert_eq!(pick_page(old, 0x1000, |v| v), Some(0x1000));
        assert_eq!(pick_page(old, 0x1_0000, |v| v), Some(0x1_0000));
        // Graviton holds 64 KiB only; a register that holds 4 KiB reads 0 for it.
        let graviton = |v: u64| {
            if (v >> 8) & 3 == 2 {
                v
            } else {
                v & !(3 << 8) | (2 << 8)
            }
        };
        assert_eq!(pick_page(old, 0x1000, graviton), Some(0x1_0000));
        let sixteen = |v: u64| {
            if (v >> 8) & 3 == 1 {
                v
            } else {
                v & !(3 << 8) | (1 << 8)
            }
        };
        assert_eq!(pick_page(old, 0x1000, sixteen), Some(0x4000));
        // Nothing held: a register that reads 3 (reserved) for every try.
        assert_eq!(pick_page(old, 0x1000, |v| v | (3 << 8)), None);
    }

    #[test]
    fn the_address_of_a_64k_table_keeps_pa_51_to_48_in_bits_15_to_12() {
        assert_eq!(baser_address(0x4_0001_0000, 0x1_0000), 0x4_0001_0000);
        assert_eq!(
            baser_address(0x000A_0000_4001_0000, 0x1_0000),
            0x0000_0000_4001_0000 | (0xA << 12)
        );
        assert_eq!(baser_address(0x4_0001_2000, 0x1000), 0x4_0001_2000);
        let b = baser(
            BASER_TYPE_DEVICE << 56,
            0x4_0001_0000,
            1,
            0x1_0000,
            SHARE_INNER,
            CACHE_RAWAWB,
        );
        assert_eq!(baser_page_size(b), 0x1_0000);
        assert_eq!(b & 0xFF, 0, "Size counts pages of 64 KiB: one page is 0");
    }

    #[test]
    fn tables_are_counted_in_pages_of_the_chosen_size() {
        // QEMU: 4 KiB pages, 8-byte entries, every ID of the map: 16 pages, IDs up to 0x1FFF.
        let q = device_table(0xFFFF, 8, 16, 0x1000);
        assert_eq!((q.entries, q.pages, q.bytes), (0x2000, 16, 0x1_0000));
        assert_eq!(block_order(q.bytes), 4);
        // Graviton: one 64 KiB page, the same IDs.
        let g = device_table(0xFFFF, 8, 16, 0x1_0000);
        assert_eq!((g.entries, g.pages, g.bytes), (0x2000, 1, 0x1_0000));
        // 16-byte entries at 64 KiB: one page, IDs up to 0xFFF.
        assert_eq!(device_table(0xFFFF, 16, 16, 0x1_0000).entries, 0x1000);
        // Devbits 8 cuts to 0xFF.
        assert_eq!(device_table(0xFFFF, 8, 8, 0x1_0000).entries, 0x100);
        // A small map needs little.
        assert_eq!(device_table(0x3F, 8, 16, 0x1000).pages, 1);
        // Collections of two CPUs at 64 KiB: one page.
        let c = collection_table(2, 8, 0x1_0000);
        assert_eq!((c.pages, c.bytes), (1, 0x1_0000));
        assert_eq!(block_order(c.bytes), 4);
    }

    #[test]
    fn gicd_typer_of_a_restricted_lpi_range_and_the_shareability_decision() {
        let t = (1 << 17) | (13 << 19) | (6 << 11);
        assert!(gicd_lpis(t));
        assert_eq!(gicd_id_bits(t), 14);
        assert_eq!(gicd_num_lpis(t), Some(128));
        assert_eq!(gicd_num_lpis(1 << 17), None);
        assert!(holds_shareability((1 << 10) | (7 << 7)));
        assert!(!holds_shareability(7 << 7), "shareability 0");
        assert!(!holds_shareability((1 << 10) | (1 << 7)), "inner cache 1");
    }

    #[test]
    fn typer_fields_of_qemu() {
        // QEMU 11: ITT entry 12 bytes, 16 EventID bits, 16 DeviceID bits [G47].
        let typer = 1 | (11 << 4) | (15 << 8) | (15 << 13) | (1 << 36);
        assert_eq!(typer_itt_entry_size(typer), 12);
        assert_eq!(typer_event_bits(typer), 16);
        assert_eq!(typer_device_bits(typer), 16);
        assert!(!typer_pta(typer));
        assert_eq!(typer_hcc(typer), 0);
        assert_eq!(processor_number(3 << 8), 3);
    }

    #[test]
    fn device_table_for_a_flat_msi_map() {
        // 64 K DeviceIDs of 8 bytes need 128 pages: past a 64 KiB table.
        assert_eq!(device_table_pages(0xFFFF, 8, 16), None);
        assert_eq!(device_table_pages(0x1FF, 8, 16), Some(1));
        assert_eq!(device_table_pages(0x200, 8, 16), Some(2));
        assert_eq!(device_table_pages(0x1FFF, 8, 16), Some(16));
        assert_eq!(collection_table_pages(8, 8), 1);
    }

    #[test]
    fn itt_sizes_follow_the_events() {
        assert_eq!(event_bits(1), 1);
        assert_eq!(event_bits(2), 1);
        assert_eq!(event_bits(3), 2);
        assert_eq!(event_bits(64), 6);
        assert_eq!(itt_bytes(64, 12), Some(768));
        assert_eq!(itt_bytes(64, 16), Some(1024));
        assert_eq!(itt_bytes(64, 17), None);
        assert_eq!(itt_bytes(65, 8), Some(1024));
        assert_eq!(itt_bytes(65, 12), None);
    }

    #[test]
    fn commands_encode_as_g46() {
        let c = Command::mapd(0x1234, 0x4800_0100, 6, true);
        assert_eq!(c.0[0], 0x08 | (0x1234 << 32));
        assert_eq!(c.0[1], 5);
        assert_eq!(c.0[2], 0x4800_0100 | 1 << 63);
        assert_eq!(Command::mapd(1, 0x100, 1, false).0[2] >> 63, 0);
        let c = Command::mapc(3, 3 << 16, true);
        assert_eq!(c.0, [0x09, 0, 3 | (3 << 16) | 1 << 63, 0]);
        let c = Command::mapti(0x10, 2, 8193, 1);
        assert_eq!(c.0, [0x0A | (0x10 << 32), 2 | (8193 << 32), 1, 0]);
        assert_eq!(Command::inv(7, 1).0, [0x0C | (7 << 32), 1, 0, 0]);
        assert_eq!(Command::discard(7, 1).0, [0x0F | (7 << 32), 1, 0, 0]);
        assert_eq!(Command::int(7, 1).0, [0x03 | (7 << 32), 1, 0, 0]);
        assert_eq!(Command::sync(2 << 16).0, [0x05, 0, 2 << 16, 0]);
        assert_eq!(Command::invall(4).0, [0x0D, 0, 4, 0]);
        assert_eq!(Command::discard(0, 0).name(), "DISCARD");
    }

    #[test]
    fn queue_arithmetic_wraps_and_keeps_a_slot_empty() {
        assert_eq!(QUEUE_SLOTS, 128);
        assert_eq!(free_slots(0, 0), 127);
        assert_eq!(free_slots(0, 127 * 32), 0);
        assert_eq!(next_offset(127 * 32), 0);
        assert_eq!(pending(0, 4 * 32), 4);
        assert_eq!(pending(126 * 32, 2 * 32), 4);
        assert_eq!(free_slots(10 * 32, 9 * 32), 0);
        assert_eq!(free_slots(10 * 32, 10 * 32), 127);
    }

    /// A fake ITS: `sent` commands, `run` of them executed.
    fn creadr_of(run: u64) -> usize {
        write_offset(run)
    }

    #[test]
    fn the_counter_gives_the_commands_run() {
        assert_eq!(write_offset(0), 0);
        assert_eq!(write_offset(128), 0);
        assert_eq!(write_offset(130), 2 * 32);
        for (sent, run) in [(0, 0), (5, 0), (5, 5), (127, 3), (128, 1), (300, 200)] {
            assert_eq!(done(sent, creadr_of(run)), run, "sent {sent} run {run}");
        }
    }

    #[test]
    fn a_target_is_reached_at_any_distance() {
        // The commands of a call went in at count 10; 96 and then more of
        // other CPUs followed, and the ITS ran them all: the ring position
        // of the target is far behind the reader, and it must read done.
        let target = 10;
        assert!(!reached(10, creadr_of(5), target));
        assert!(reached(10, creadr_of(10), target));
        assert!(reached(106, creadr_of(106), target));
        assert!(reached(106, creadr_of(106 - 1), target));
        assert!(reached(10 + 5 * 128 + 3, creadr_of(10 + 5 * 128), target));
        // Past 2^32 commands the counter still compares.
        let big = (1u64 << 32) + 7;
        assert!(!reached(big + 4, creadr_of(big - 1), big));
        assert!(reached(big + 4, creadr_of(big), big));
        assert!(reached(big + 4, creadr_of(big + 4), big + 4));
        assert_eq!(done(big + 4, creadr_of(big)), big);
    }

    #[test]
    fn a_ring_wide_gap_between_the_target_and_the_reader_is_still_ahead() {
        // The reader looks at a target that is 100 commands behind the ITS.
        let sent = 1000;
        assert!(reached(sent, creadr_of(sent - 3), sent - 100));
        assert!(!reached(sent, creadr_of(sent - 3), sent - 2));
    }

    #[test]
    fn room_keeps_the_slots_of_a_section() {
        // Empty queue: 127 slots.
        assert!(room(0, 0, 127, 0));
        assert!(!room(0, 0, 128, 0));
        // A sender outside OBJ leaves QUEUE_KEEP of them.
        assert!(room(0, 0, 127 - QUEUE_KEEP, QUEUE_KEEP));
        assert!(!room(0, 0, 127 - QUEUE_KEEP + 1, QUEUE_KEEP));
        // 120 commands outstanding: a section's 4 fit, another sender's 4 do not.
        assert!(room(120, 0, 4, 0));
        assert!(!room(120, 0, 4, QUEUE_KEEP));
        assert!(room(120, 0, 3, 0));
        // A lap later: the same.
        assert!(room(120 + 128, 128, 4, 0));
        assert!(!room(120 + 128, 128, 4, QUEUE_KEEP));
        // A count that lags the truth only takes room away.
        assert!(!room(120, 0, 8, 0));
        assert!(room(120, 100, 8, 0));
    }

    /// A fake ITS the test drives: it counts the commands sent and run, has
    /// room for `space` more, and says what the stall clock says.
    struct Fake {
        sent: u64,
        run: u64,
        space: usize,
        sends: usize,
        look: bool,
        stalled: bool,
    }

    impl Fake {
        fn new(sent: u64, run: u64, space: usize) -> Fake {
            Fake {
                sent,
                run,
                space,
                sends: 0,
                look: true,
                stalled: false,
            }
        }

        fn step(&mut self, w: &mut Wait) -> Step {
            let (sent, run, space, look, stalled) = (
                &mut self.sent,
                self.run,
                self.space,
                self.look,
                self.stalled,
            );
            let sends = &mut self.sends;
            w.step(
                || {
                    *sends += 1;
                    (space >= 3).then(|| {
                        *sent += 3;
                        *sent
                    })
                },
                || look.then_some(run),
                || stalled,
            )
        }
    }

    #[test]
    fn a_wait_sends_once_and_finishes_when_the_commands_ran() {
        let mut q = Fake::new(100, 100, 10);
        let mut w = Wait::new();
        // Sent, not run: again, twice; the commands went in once.
        assert_eq!(q.step(&mut w), Step::Again);
        assert_eq!(q.step(&mut w), Step::Again);
        assert_eq!(q.sends, 1);
        assert_eq!(q.sent, 103);
        q.run = 102;
        assert_eq!(q.step(&mut w), Step::Again);
        q.run = 103;
        assert_eq!(q.step(&mut w), Step::Done);
        assert_eq!(q.sends, 1);
    }

    #[test]
    fn a_wait_with_no_room_asks_again_and_sends_nothing() {
        let mut q = Fake::new(0, 0, 2);
        let mut w = Wait::new();
        assert_eq!(q.step(&mut w), Step::Again);
        assert_eq!(q.step(&mut w), Step::Again);
        assert_eq!(q.sent, 0);
        assert_eq!(q.sends, 2);
        q.space = 3;
        assert_eq!(q.step(&mut w), Step::Again);
        assert_eq!(q.sent, 3);
        q.run = 3;
        assert_eq!(q.step(&mut w), Step::Done);
    }

    #[test]
    fn a_wait_without_a_consistent_look_is_not_yet_and_never_a_stop() {
        // Another CPU adds commands at each look: no look is had; the
        // portion waited a long time for its turn, and the ITS is fine.
        let mut q = Fake::new(10, 10, 10);
        let mut w = Wait::new();
        assert_eq!(q.step(&mut w), Step::Again);
        q.look = false;
        for _ in 0..5 {
            assert_eq!(q.step(&mut w), Step::Again);
        }
        q.look = true;
        q.run = q.sent;
        assert_eq!(q.step(&mut w), Step::Done);
    }

    #[test]
    fn a_wait_stops_only_when_the_clock_says_the_its_did() {
        let mut q = Fake::new(0, 0, 10);
        let mut w = Wait::new();
        assert_eq!(q.step(&mut w), Step::Again);
        q.stalled = true;
        assert_eq!(q.step(&mut w), Step::Stalled);
        // Commands that ran are done, whatever the clock says.
        q.run = q.sent;
        assert_eq!(q.step(&mut w), Step::Done);
        // A queue with no room for long is a stop too.
        let mut q = Fake::new(0, 0, 0);
        q.stalled = true;
        assert_eq!(
            Wait::new().step(|| None, || Some(0), || q.stalled),
            Step::Stalled
        );
    }

    #[test]
    fn the_stall_clock_counts_the_its_not_the_portion() {
        let limit = 1000;
        // The ITS advanced at 4990 and commands went in at 4995; a portion
        // that comes at 5000 after waiting for its turn finds no stop.
        assert!(!stalled(5000, 4990, 4995, limit));
        // Advanced long ago, but commands went in just now.
        assert!(!stalled(5000, 10, 4990, limit));
        // Sent long ago, advanced just now.
        assert!(!stalled(5000, 4990, 10, limit));
        // Neither for more than the limit: stopped.
        assert!(stalled(5000, 3000, 3999, limit));
        assert!(!stalled(5000, 3000, 4000, limit));
    }

    #[test]
    fn lpi_map_hands_out_the_lowest_and_runs_dry() {
        let mut m = LpiMap::new();
        assert_eq!(m.take(), Some(8192));
        assert_eq!(m.take(), Some(8193));
        m.give(8192);
        assert_eq!(m.take(), Some(8192));
        for _ in 2..MAX_LPIS {
            assert!(m.take().is_some());
        }
        assert_eq!(m.take(), None);
        assert_eq!(m.in_use(), MAX_LPIS);
        m.give(8192 + 1023);
        assert_eq!(m.take(), Some(8192 + 1023));
    }

    #[test]
    #[should_panic(expected = "twice")]
    fn an_lpi_given_back_twice_stops() {
        let mut m = LpiMap::new();
        let n = m.take().unwrap();
        m.give(n);
        m.give(n);
    }

    /// A virtual ITS that takes the addresses of the command queue and the
    /// property table with the accuracy of 64 KiB, as the one of EC2 seems to.
    struct Vits64k;

    impl Vits64k {
        fn seen(reg: u64) -> u64 {
            reg & 0x000F_FFFF_FFFF_0000
        }
    }

    /// The allocator the kernel takes its blocks from: a block of `order` on
    /// the first boundary of its own size at or after `cursor`.
    fn take(cursor: &mut u64, order: u8) -> u64 {
        let size = 0x1000u64 << order;
        let pa = cursor.next_multiple_of(size);
        *cursor = pa + size;
        pa
    }

    #[test]
    fn the_queue_and_the_property_table_lie_where_a_64k_reader_looks() {
        // Free memory that starts at an address of the layout of run 1201,
        // which is a multiple of 4 KiB only.
        for start in [0x77bf_1000u64, 0x77bf_2000, 0x781d_e000, 0x77bf_9000] {
            let mut cursor = start;
            let queue = take(&mut cursor, QUEUE_ORDER);
            let prop = take(&mut cursor, PROP_ORDER);
            let cb = cbaser(queue, 1, SHARE_INNER, CACHE_RAWAWB);
            let pb = propbaser(prop, ID_BITS, SHARE_INNER, CACHE_RAWAWB);
            assert_eq!(Vits64k::seen(cb), queue, "commands are read elsewhere");
            assert_eq!(Vits64k::seen(pb), prop, "properties are read elsewhere");
            assert!(table_aligned(queue) && table_aligned(prop));
        }
    }

    #[test]
    fn the_read_back_sees_an_address_the_register_does_not_hold() {
        let wrote = cbaser(0x77bf_9000, 1, SHARE_INNER, CACHE_RAWAWB);
        let read = (wrote & !ADDR_4K) | Vits64k::seen(wrote);
        let err = verify("GITS_CBASER", wrote, read, CBASER_CHECK).unwrap_err();
        assert_eq!(err.reg, "GITS_CBASER");
        assert!(
            err.to_string().starts_with("GITS_CBASER reads back 0x"),
            "{err}"
        );
        verify("GITS_CBASER", wrote, wrote, CBASER_CHECK).unwrap();
        // The shareability fields may differ.
        verify("GITS_CBASER", wrote, wrote & !(3 << 10), CBASER_CHECK).unwrap();
    }

    #[test]
    fn a_baser_that_drops_bits_15_to_12_of_a_64k_table_reads_back_wrong() {
        let old = (BASER_TYPE_DEVICE << 56) | (7 << 48) | (2 << 8);
        let pa = 0x7_8863_0000 | (0x1 << 48);
        let wrote = baser(old, pa, 1, 0x1_0000, SHARE_INNER, CACHE_RAWAWB);
        let read = wrote & !(0xF << 12);
        assert!(verify("GITS_BASER0", wrote, read, baser_check(0x1_0000)).is_err());
        assert!(verify("GITS_BASER0", wrote, wrote, baser_check(0x1_0000)).is_ok());
        // A 4 KiB page keeps the whole address.
        let w4 = baser(old, 0x7_8863_2000, 1, 0x1000, SHARE_INNER, CACHE_RAWAWB);
        assert!(verify("GITS_BASER0", w4, w4 & !(1 << 13), baser_check(0x1000)).is_err());
    }

    #[test]
    fn the_propbaser_and_pendbaser_addresses_are_read_back() {
        let p = propbaser(0x77bf_2000, ID_BITS, SHARE_INNER, CACHE_RAWAWB);
        let low = p & !(0xF << 12);
        assert!(verify("GICR_PROPBASER", p, low, PROPBASER_CHECK).is_err());
        let q = pendbaser(0x77c1_0000, SHARE_INNER, CACHE_RAWAWB);
        // PTZ reads as 0.
        assert!(verify("GICR_PENDBASER", q, q & !(1 << 62), PENDBASER_CHECK).is_ok());
        assert!(verify("GICR_PENDBASER", q, q ^ (1 << 16), PENDBASER_CHECK).is_err());
    }

    #[test]
    fn the_tables_line_shows_physical_addresses() {
        let t = Tables {
            queue: 0x77c0_0000,
            prop: 0x77c1_0000,
            pend: &[0x77c2_0000, 0x77c3_0000],
            dt: 0x77c4_0000,
            ct: 0x77c5_0000,
        };
        let line = format!("{t}");
        assert_eq!(
            line,
            "its tables queue 0x77c00000 prop 0x77c10000 pend0 0x77c20000 pend1 0x77c30000 dt 0x77c40000 ct 0x77c50000"
        );
    }

    #[test]
    fn a_self_test_that_lost_an_lpi_names_the_cpu() {
        assert_eq!(verdict(&[Some(10), Some(20)]), Ok(()));
        assert_eq!(verdict(&[]), Ok(()));
        let err = verdict(&[Some(10), None]).unwrap_err();
        assert_eq!(err, NotDelivered { cpu: 1, lpi: 8193 });
        assert_eq!(format!("{err}"), "LPI 8193 did not reach CPU 1");
        assert_eq!(
            format!("{}", verdict(&[None, None]).unwrap_err()),
            "LPI 8192 did not reach CPU 0"
        );
    }

    #[test]
    fn enable_lpis_left_by_the_firmware_is_cleared_or_the_its_stays_off() {
        use core::cell::Cell;
        // A redistributor that takes the write.
        let reg = Cell::new(GICR_CTLR_ENABLE_LPIS | 0x10);
        let waits = Cell::new(0);
        let r = clear_enable_lpis(|| reg.get(), |v| reg.set(v), || waits.set(waits.get() + 1));
        assert_eq!(r, Ok(()));
        assert_eq!(reg.get(), 0x10, "the other bits stay");
        assert_eq!(waits.get(), 1);
        // Clear at entry: no write and no wait.
        let r = clear_enable_lpis(|| reg.get(), |_| panic!("no write"), || panic!("no wait"));
        assert_eq!(r, Ok(()));
        // A redistributor that keeps the bit.
        let stuck = Cell::new(GICR_CTLR_ENABLE_LPIS);
        let r = clear_enable_lpis(|| stuck.get(), |_| {}, || {});
        assert_eq!(r, Err(GICR_CTLR_ENABLE_LPIS));
    }
}
