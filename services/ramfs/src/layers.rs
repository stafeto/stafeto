// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Layers: a package file (`.stpkg`) mapped into the service shows its table `rootfs` as names
//! in the one tree. The entries of a layer take places of the image above the entries of the
//! system's table (`ENTRIES_MAX ..`), so the code that reads, opens and executes a file of the
//! image serves a file of a layer unchanged.
//!
//! Attaching runs in portions, one job at a time: the mapping is made by the thread of the
//! service that maps (`Mapping`), then the table is checked without any visible change
//! (`Checking`), then the names are inserted (`Inserting`). A conflict in the last phase
//! takes the inserted names out again (`RollingBack`) and reports the entry. Detaching takes
//! the names out in the opposite order (`Detaching`). A place whose file is still held (an open
//! description, a loading program) waits (`Draining`) until the last holder lets go, and only
//! a layer without places goes to the release queue (`Released`), where the service unmaps it
//! and tells its client.
//!
//! The directories a layer brings are not nodes of their own unless the path is free: a
//! directory whose path exists is merged (its place is a hidden link to the node found), and a
//! new one takes a place of the reserve (`LAYER_DIRS`) with a copy of its name, owned by the
//! layers that name it.

use super::*;
use bootimg::rootfs::{self, Rootfs};
use bootimg::{BootImage, PACKAGE};
use proto_fs::{
    ALREADY_EXISTS, BAD_LAYER, BAD_MODE, BUSY, CONFLICT, LayerReply, PERMISSION,
    READ_ONLY_FILESYSTEM,
};

/// The layers at once: the 64 windows the service maps them at.
pub const LAYERS_MAX: usize = 64;
/// The entries of one layer at most (`pkgfmt::container::ENTRIES_MAX`).
pub const LAYER_ENTRIES: usize = 1024;
/// The container files of a package: meta, rootfs, manifest and one per entry at most.
const CONTAINER_FILES_MAX: usize = 3 + LAYER_ENTRIES;
/// The depth of the directories of a path: 511 bytes hold 255 names.
const DEPTH_MAX: usize = 256;
const NO_LAYER: u8 = u8::MAX;
/// `entry` of a refusal that names no entry of the table.
pub const NO_ENTRY_NUMBER: u32 = u32::MAX;

/// Entries one step of the check visits, and the bytes of their paths.
pub const CHECK_ENTRIES: usize = 16;
pub const CHECK_BYTES: usize = 1536;
/// Entries one step of the insertion takes in, the bytes of their names and the links of
/// name chains it follows.
pub const INSERT_ENTRIES: usize = 8;
pub const INSERT_BYTES: usize = 1024;
pub const INSERT_LINKS: usize = 32;
/// Entries one step of the detach takes out, and the bytes of their names.
pub const DETACH_ENTRIES: usize = 32;
pub const DETACH_BYTES: usize = 1024;

/// What a step may do. The layers of the boot image run with `Limits::WHOLE`.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub check_entries: usize,
    pub check_bytes: usize,
    pub insert_entries: usize,
    pub insert_bytes: usize,
    pub insert_links: usize,
    pub detach_entries: usize,
    pub detach_bytes: usize,
}
impl Limits {
    pub const PORTIONS: Self = Self {
        check_entries: CHECK_ENTRIES,
        check_bytes: CHECK_BYTES,
        insert_entries: INSERT_ENTRIES,
        insert_bytes: INSERT_BYTES,
        insert_links: INSERT_LINKS,
        detach_entries: DETACH_ENTRIES,
        detach_bytes: DETACH_BYTES,
    };
    pub const WHOLE: Self = Self {
        check_entries: usize::MAX,
        check_bytes: usize::MAX,
        insert_entries: usize::MAX,
        insert_bytes: usize::MAX,
        insert_links: usize::MAX,
        detach_entries: usize::MAX,
        detach_bytes: usize::MAX,
    };
}

/// Where a layer is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayerState {
    Free,
    /// The mapping thread maps the object.
    Mapping,
    Checking,
    Inserting,
    /// Taking the inserted names out after a refusal; `failure` says what to answer.
    RollingBack,
    Attached,
    Detaching,
    /// No names; places still held by open files or loading programs.
    Draining,
    /// No places: the service unmaps it and tells the client, then forgets it.
    Released,
}

#[derive(Clone, Copy)]
struct Chain {
    started: bool,
    bucket: u16,
    stamp: u32,
    link: u16,
}
impl Chain {
    const START: Self = Self {
        started: false,
        bucket: 0,
        stamp: 0,
        link: NONE,
    };
}

#[derive(Clone, Copy)]
pub(crate) struct Layer {
    state: LayerState,
    number: u32,
    /// A layer of the boot image: it has no client, no mapping to give back, no detach.
    image: bool,
    /// Nobody waits for the answers: the client left. The work goes on without them.
    orphan: bool,
    count: u16,
    files: u32,
    rootfs_offset: u32,
    rootfs_length: u32,
    time: u64,
    /// Places the layer holds, with or without a name.
    occupied: u16,
    /// The next entry of the walk the state names (the check and the insertion count up, the
    /// detach and the rollback count down).
    cursor: u16,
    names: u32,
    failure: Option<(u32, u32)>,
    chain: Chain,
}
impl Layer {
    const FREE: Self = Self {
        state: LayerState::Free,
        number: 0,
        image: false,
        orphan: false,
        count: 0,
        files: 0,
        rootfs_offset: 0,
        rootfs_length: 0,
        time: 0,
        occupied: 0,
        cursor: 0,
        names: 0,
        failure: None,
        chain: Chain::START,
    };
}

#[derive(Clone, Copy)]
struct Map {
    pointer: *const u8,
    length: usize,
}

const PLACE_FILE: u8 = 1;
const PLACE_DIR: u8 = 2;

/// An entry of a layer in the place it took.
#[derive(Clone, Copy)]
pub(crate) struct Place {
    layer: u8,
    kind: u8,
    name_length: u8,
    /// A file: the place of the node of its file (the first entry that names the file; it is
    /// this place for the first). A directory: the place of the reserve it owns, or `NONE`.
    first: u16,
    name_offset: u32,
    data_offset: u32,
    data_length: u32,
}
impl Place {
    const FREE: Self = Self {
        layer: NO_LAYER,
        kind: 0,
        name_length: 0,
        first: NONE,
        name_offset: 0,
        data_offset: 0,
        data_length: 0,
    };
}

/// A directory some layer created: its name, kept here, and how many entries of layers name it.
#[derive(Clone, Copy)]
pub(crate) struct ReserveDir {
    name: [u8; 255],
    length: u8,
    owners: u16,
    queued: bool,
}
impl ReserveDir {
    const FREE: Self = Self {
        name: [0; 255],
        length: 0,
        owners: 0,
        queued: false,
    };
}

/// What the check of the running attach has learned.
struct Job {
    layer: u8,
    /// The entry that is the parent of each entry, `NONE` for `/`.
    parent: [u16; LAYER_ENTRIES],
    /// The first entry of each container file.
    first_of_file: [u16; CONTAINER_FILES_MAX],
    /// The directories above the entry being checked, as entry numbers.
    stack: [u16; DEPTH_MAX],
    depth: u16,
}
impl Job {
    const NONE: Self = Self {
        layer: NO_LAYER,
        parent: [NONE; LAYER_ENTRIES],
        first_of_file: [NONE; CONTAINER_FILES_MAX],
        stack: [NONE; DEPTH_MAX],
        depth: 0,
    };
}

/// The layers of the service.
pub(crate) struct Layers {
    layers: [Layer; LAYERS_MAX],
    maps: [Map; LAYERS_MAX],
    /// The place of each entry of each layer, `NONE` before it is inserted and after it is out.
    entry_place: [[u16; LAYER_ENTRIES]; LAYERS_MAX],
    places: [Place; LAYER_SLOTS],
    reserve: [ReserveDir; LAYER_DIRS],
    slot_free: [u16; LAYER_SLOTS],
    slot_len: usize,
    reserve_free: [u16; LAYER_DIRS],
    reserve_len: usize,
    job: Job,
    /// Layers that have no places and wait for the service to unmap them.
    released: [u8; LAYERS_MAX],
    released_head: usize,
    released_len: usize,
    /// Reserve directories that lost their last name and may have lost their last owner.
    queue: [u8; LAYER_DIRS],
    queue_head: usize,
    queue_len: usize,
}
impl Layers {
    pub(crate) const fn new() -> Self {
        Self {
            layers: [Layer::FREE; LAYERS_MAX],
            maps: [Map {
                pointer: core::ptr::null(),
                length: 0,
            }; LAYERS_MAX],
            entry_place: [[NONE; LAYER_ENTRIES]; LAYERS_MAX],
            places: [Place::FREE; LAYER_SLOTS],
            reserve: [ReserveDir::FREE; LAYER_DIRS],
            slot_free: [0; LAYER_SLOTS],
            slot_len: LAYER_SLOTS,
            reserve_free: [0; LAYER_DIRS],
            reserve_len: LAYER_DIRS,
            job: Job::NONE,
            released: [0; LAYERS_MAX],
            released_head: 0,
            released_len: 0,
            queue: [0; LAYER_DIRS],
            queue_head: 0,
            queue_len: 0,
        }
    }

    pub(crate) fn initialize(&mut self) {
        self.layers.fill(Layer::FREE);
        self.maps.fill(Map {
            pointer: core::ptr::null(),
            length: 0,
        });
        for map in self.entry_place.iter_mut() {
            map.fill(NONE);
        }
        self.places.fill(Place::FREE);
        self.reserve.fill(ReserveDir::FREE);
        for (i, free) in self.slot_free.iter_mut().enumerate() {
            *free = (LAYER_SLOTS - i - 1) as u16;
        }
        self.slot_len = LAYER_SLOTS;
        for (i, free) in self.reserve_free.iter_mut().enumerate() {
            *free = (LAYER_DIRS - i - 1) as u16;
        }
        self.reserve_len = LAYER_DIRS;
        self.job.layer = NO_LAYER;
        self.released_head = 0;
        self.released_len = 0;
        self.queue_head = 0;
        self.queue_len = 0;
    }
}

/// A layer that has no places left.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Released {
    pub index: usize,
    pub number: u32,
    /// Whether the attach failed (the client has its answer already) or the layer was detached.
    pub failed: bool,
    pub image: bool,
}

const SLOT_BASE: usize = ENTRIES_MAX;
const RESERVE_BASE: usize = ENTRIES_MAX + LAYER_SLOTS;

fn refuse(status: u32, entry: u32) -> LayerReply {
    LayerReply::Entry { status, entry }
}

fn refused(status: u32) -> LayerReply {
    match status {
        BAD_LAYER | BAD_MODE | CONFLICT => refuse(status, NO_ENTRY_NUMBER),
        other => LayerReply::Refused { status: other },
    }
}

/// The error of the table, as the layer answers it.
fn bad_layer(entry: u32) -> LayerReply {
    refuse(BAD_LAYER, entry)
}

impl Storage<'_> {
    /// Whether place `b` of the image is in the part that layers own.
    pub(crate) fn is_layer_place(b: usize) -> bool {
        (SLOT_BASE..BOOT_SPACE).contains(&b)
    }

    /// Whether the name at entry `index` of `originals` is a name that layers brought.
    pub(crate) fn is_layer_name(index: usize) -> bool {
        (4 + SLOT_BASE..4 + BOOT_SPACE).contains(&index)
    }

    /// Whether `token` names a node that belongs to a layer: a file, a link or a directory
    /// that a layer brought.
    pub(crate) fn is_layer_node(&self, token: Token) -> bool {
        self.node(token).is_ok_and(|n| {
            n.boot != NONE && Self::is_layer_place(n.boot as usize) && token.slot == 5 + n.boot
        })
    }

    /// The name of place `b` of the image above the entries of the system's table.
    pub(crate) fn layer_name(&self, b: usize) -> &[u8] {
        if b < RESERVE_BASE {
            let place = &self.state.layers.places[b - SLOT_BASE];
            if place.layer == NO_LAYER {
                return &[];
            }
            let bytes = self.layer_bytes(place.layer as usize);
            &bytes[place.name_offset as usize..][..place.name_length as usize]
        } else {
            let dir = &self.state.layers.reserve[b - RESERVE_BASE];
            &dir.name[..dir.length as usize]
        }
    }

    /// The bytes of the file of the node whose first place is `b`.
    pub(crate) fn layer_data(&self, b: usize) -> &'static [u8] {
        let place = &self.state.layers.places[b - SLOT_BASE];
        if place.layer == NO_LAYER || place.kind != PLACE_FILE {
            return &[];
        }
        let bytes = self.layer_bytes(place.layer as usize);
        &bytes[place.data_offset as usize..][..place.data_length as usize]
    }

    /// The mapping of a layer.
    ///
    /// The mapping lives from the moment the service gives it to `layer_mapped` until
    /// `layer_forget`, which `layer_next_release` offers only for a layer without any place;
    /// no slice outlives the step that took it.
    fn layer_bytes<'x>(&self, index: usize) -> &'x [u8] {
        let map = self.state.layers.maps[index];
        if map.pointer.is_null() {
            return &[];
        }
        // SAFETY: see above; the pointer and the length are those of a mapping whose length the
        // service checked when it gave it.
        unsafe { core::slice::from_raw_parts(map.pointer, map.length) }
    }

    fn layer_rootfs<'x>(&self, index: usize) -> Rootfs<'x> {
        let layer = &self.state.layers.layers[index];
        let bytes = self.layer_bytes(index);
        let table = &bytes[layer.rootfs_offset as usize..][..layer.rootfs_length as usize];
        Rootfs::open(table, layer.files).expect("the table was opened by layer_mapped")
    }

    fn layer_index(&self, number: u32) -> Option<usize> {
        self.state
            .layers
            .layers
            .iter()
            .position(|l| l.state != LayerState::Free && l.number == number)
    }

    /// The state of the layer with this number.
    pub fn layer_state(&self, number: u32) -> Option<LayerState> {
        self.layer_index(number)
            .map(|i| self.state.layers.layers[i].state)
    }

    /// Whether the layer with this number is one of the boot image.
    pub fn layer_is_image(&self, number: u32) -> bool {
        self.layer_index(number)
            .is_some_and(|i| self.state.layers.layers[i].image)
    }

    /// The places that are free for entries of layers.
    pub fn layer_places_free(&self) -> usize {
        self.state.layers.slot_len
    }

    /// The directories of the reserve that are free.
    pub fn layer_dirs_free(&self) -> usize {
        self.state.layers.reserve_len
    }

    /// The layers that are not free.
    pub fn layers_in_use(&self) -> usize {
        self.state
            .layers
            .layers
            .iter()
            .filter(|l| l.state != LayerState::Free)
            .count()
    }

    /// Whether a job of a layer is running.
    pub fn layer_job(&self) -> Option<u32> {
        let layer = self.state.layers.job.layer;
        (layer != NO_LAYER).then(|| self.state.layers.layers[layer as usize].number)
    }

    /// The names of the layer now in the tree.
    pub fn layer_names(&self, number: u32) -> u32 {
        self.layer_index(number)
            .map_or(0, |i| self.state.layers.layers[i].names)
    }

    // ---- Attach ----------------------------------------------------------------------------

    /// Begins an attach of layer `number`; the object is not mapped yet. Gives the index of
    /// the record, which the mapping thread's result is addressed to.
    pub fn layer_begin_attach(&mut self, number: u32, image: bool) -> Result<usize, u32> {
        if self.layer_index(number).is_some() {
            return Err(ALREADY_EXISTS);
        }
        if self.state.layers.job.layer != NO_LAYER {
            return Err(BUSY);
        }
        let index = self
            .state
            .layers
            .layers
            .iter()
            .position(|l| l.state == LayerState::Free)
            .ok_or(proto_fs::NO_SPACE)?;
        self.state.layers.layers[index] = Layer {
            state: LayerState::Mapping,
            number,
            image,
            ..Layer::FREE
        };
        self.state.layers.entry_place[index].fill(NONE);
        self.state.layers.job.layer = index as u8;
        Ok(index)
    }

    /// The mapping is made: reads the header and the bounds of the table, which is all that is
    /// checked in this step. The error is what to answer; the caller then gives the layer up
    /// with `layer_unmapped`.
    pub fn layer_mapped(
        &mut self,
        index: usize,
        pointer: *const u8,
        length: usize,
    ) -> Result<(), LayerReply> {
        let layers = &mut self.state.layers;
        debug_assert_eq!(layers.layers[index].state, LayerState::Mapping);
        layers.maps[index] = Map { pointer, length };
        if length == 0 || length > u32::MAX as usize {
            return Err(bad_layer(NO_ENTRY_NUMBER));
        }
        let bytes = self.layer_bytes(index);
        let view = BootImage::view_as(bytes, &PACKAGE).map_err(|_| bad_layer(NO_ENTRY_NUMBER))?;
        if view.count() < 3 || view.count() as usize > CONTAINER_FILES_MAX {
            return Err(bad_layer(NO_ENTRY_NUMBER));
        }
        let file = view
            .file(1)
            .ok()
            .filter(|f| f.name == "rootfs")
            .ok_or_else(|| bad_layer(NO_ENTRY_NUMBER))?;
        let table =
            Rootfs::open(file.data, view.count()).map_err(|_| bad_layer(NO_ENTRY_NUMBER))?;
        if table.len() > LAYER_ENTRIES {
            return Err(bad_layer(NO_ENTRY_NUMBER));
        }
        if table.len() > self.state.layers.slot_len {
            return Err(LayerReply::Refused {
                status: proto_fs::NO_SPACE,
            });
        }
        let layers = &mut self.state.layers;
        let layer = &mut layers.layers[index];
        layer.state = LayerState::Checking;
        layer.count = table.len() as u16;
        layer.files = view.count();
        layer.rootfs_offset = file.offset as u32;
        layer.rootfs_length = file.data.len() as u32;
        layer.time = table.time();
        layer.cursor = 0;
        layers.job.parent.fill(NONE);
        layers.job.first_of_file.fill(NONE);
        layers.job.depth = 0;
        Ok(())
    }

    /// The attach ended without a layer: nothing was mapped or the mapping is gone. Frees the
    /// record.
    pub fn layer_unmapped(&mut self, index: usize) {
        let layers = &mut self.state.layers;
        debug_assert_eq!(layers.layers[index].occupied, 0);
        layers.layers[index] = Layer::FREE;
        layers.maps[index] = Map {
            pointer: core::ptr::null(),
            length: 0,
        };
        if layers.job.layer == index as u8 {
            layers.job.layer = NO_LAYER;
        }
    }

    /// One step of the running job of layer `number`, asked for by the client.
    pub fn layer_step(
        &mut self,
        number: u32,
        now: proto_fs::Timestamp,
        limits: &Limits,
    ) -> LayerReply {
        let Some(index) = self.layer_index(number) else {
            return LayerReply::Refused {
                status: proto_fs::NO_ENTRY,
            };
        };
        if self.state.layers.job.layer != index as u8 {
            return LayerReply::Refused {
                status: proto_fs::NO_ENTRY,
            };
        }
        if self.state.layers.layers[index].orphan {
            return LayerReply::Refused { status: BUSY };
        }
        self.layer_work_step(index, now, limits)
    }

    fn layer_work_step(
        &mut self,
        index: usize,
        now: proto_fs::Timestamp,
        limits: &Limits,
    ) -> LayerReply {
        match self.state.layers.layers[index].state {
            LayerState::Checking => self.check_step(index, limits),
            LayerState::Inserting => self.insert_step(index, now, limits),
            LayerState::RollingBack | LayerState::Detaching => self.detach_step(index, limits),
            _ => LayerReply::Refused { status: BUSY },
        }
    }

    fn check_step(&mut self, index: usize, limits: &Limits) -> LayerReply {
        let table = self.layer_rootfs(index);
        let (count, files) = {
            let layer = &self.state.layers.layers[index];
            (layer.count as usize, layer.files)
        };
        let mut bytes = 0;
        let mut done = 0;
        while self.state.layers.layers[index].cursor as usize != count
            && done < limits.check_entries
            && bytes < limits.check_bytes
        {
            let i = self.state.layers.layers[index].cursor as usize;
            let entry = match table.entry_checked(i as u32) {
                Ok(entry) => entry,
                Err(_) => return self.check_failed(index, bad_layer(i as u32)),
            };
            bytes += entry.path.len();
            done += 1;
            if i > 0 {
                let previous = table.entry_checked(i as u32 - 1).expect("checked before");
                if previous.path >= entry.path {
                    return self.check_failed(index, bad_layer(i as u32));
                }
            }
            if table.check_entry(i as u32, files).is_err() {
                return self.check_failed(index, bad_layer(i as u32));
            }
            if entry.mode & 0o7000 != 0 || entry.uid != 0 || entry.gid != 0 {
                return self.check_failed(index, refuse(BAD_MODE, i as u32));
            }
            let job = &mut self.state.layers.job;
            if !entry.is_directory() {
                let slot = &mut job.first_of_file[entry.file as usize];
                if *slot == NONE {
                    *slot = i as u16;
                } else {
                    let first = table.entry(u32::from(*slot));
                    if (first.mode, first.uid, first.gid) != (entry.mode, entry.uid, entry.gid) {
                        return self.check_failed(index, bad_layer(i as u32));
                    }
                }
            }
            // The parent is the nearest directory above on the stack; the stack holds the
            // directories that are prefixes of the path.
            let parent_length = entry.path.rfind('/').unwrap_or(0);
            while job.depth > 0 {
                let top = table.entry(u32::from(job.stack[job.depth as usize - 1]));
                let prefix = entry.path.len() > top.path.len()
                    && entry.path.starts_with(top.path)
                    && entry.path.as_bytes()[top.path.len()] == b'/';
                if prefix {
                    break;
                }
                job.depth -= 1;
            }
            if parent_length == 0 {
                job.parent[i] = NONE;
            } else {
                let Some(&top) = job.stack[..job.depth as usize].last() else {
                    return self.check_failed(index, bad_layer(i as u32));
                };
                if table.entry(u32::from(top)).path.len() != parent_length {
                    return self.check_failed(index, bad_layer(i as u32));
                }
                job.parent[i] = top;
            }
            if entry.is_directory() {
                if job.depth as usize == DEPTH_MAX {
                    return self.check_failed(index, bad_layer(i as u32));
                }
                job.stack[job.depth as usize] = i as u16;
                job.depth += 1;
            }
            self.state.layers.layers[index].cursor += 1;
        }
        if self.state.layers.layers[index].cursor as usize == count {
            let layer = &mut self.state.layers.layers[index];
            layer.state = LayerState::Inserting;
            layer.cursor = 0;
            layer.chain = Chain::START;
        }
        LayerReply::Resolving
    }

    /// The check found a fault: nothing was changed, the layer goes out.
    fn check_failed(&mut self, index: usize, reply: LayerReply) -> LayerReply {
        if let LayerReply::Entry { status, entry } = reply {
            self.state.layers.layers[index].failure = Some((status, entry));
        }
        self.layer_end(index);
        reply
    }

    /// A layer that holds no place leaves: the job ends, the layer goes to the release queue.
    fn layer_end(&mut self, index: usize) {
        let layers = &mut self.state.layers;
        layers.layers[index].state = if layers.layers[index].occupied == 0 {
            LayerState::Released
        } else {
            LayerState::Draining
        };
        if layers.job.layer == index as u8 {
            layers.job.layer = NO_LAYER;
        }
        self.layer_check_released(index);
    }

    fn layer_check_released(&mut self, index: usize) {
        let layers = &mut self.state.layers;
        let layer = &mut layers.layers[index];
        if matches!(layer.state, LayerState::Draining) && layer.occupied == 0 {
            layer.state = LayerState::Released;
        }
        if layer.state == LayerState::Released {
            let tail = (layers.released_head + layers.released_len) % LAYERS_MAX;
            layers.released[tail] = index as u8;
            layers.released_len += 1;
        }
    }

    /// The oldest layer that has no place left, taken off the queue. The service unmaps it,
    /// tells its client and calls `layer_unmapped`.
    pub fn layer_next_released(&mut self) -> Option<Released> {
        let layers = &mut self.state.layers;
        if layers.released_len == 0 {
            return None;
        }
        let index = layers.released[layers.released_head] as usize;
        layers.released_head = (layers.released_head + 1) % LAYERS_MAX;
        layers.released_len -= 1;
        let layer = &layers.layers[index];
        Some(Released {
            index,
            number: layer.number,
            failed: layer.failure.is_some(),
            image: layer.image,
        })
    }

    /// The parent node an entry goes under: `/`, or the directory of the entry above it, which
    /// must still be there.
    fn layer_parent(&self, index: usize, entry: usize) -> Result<Token, ()> {
        let parent = self.state.layers.job.parent[entry];
        if parent == NONE {
            return Ok(ROOT);
        }
        let place = self.state.layers.entry_place[index][parent as usize];
        if place == NONE {
            return Err(());
        }
        let token = self.state.originals[4 + place as usize].node;
        match self.node(token) {
            Ok(node) if node.kind == crate::DIR => Ok(token),
            _ => Err(()),
        }
    }

    fn insert_step(
        &mut self,
        index: usize,
        now: proto_fs::Timestamp,
        limits: &Limits,
    ) -> LayerReply {
        let table = self.layer_rootfs(index);
        let count = self.state.layers.layers[index].count as usize;
        let mut bytes = 0;
        let mut links = 0;
        let mut done = 0;
        while self.state.layers.layers[index].cursor as usize != count {
            if done >= limits.insert_entries
                || bytes >= limits.insert_bytes
                || links >= limits.insert_links
            {
                return LayerReply::Resolving;
            }
            let i = self.state.layers.layers[index].cursor as usize;
            let entry = table.entry(i as u32);
            let Ok(parent) = self.layer_parent(index, i) else {
                return self.insert_failed(index, refuse(CONFLICT, i as u32));
            };
            let name_start = entry.path.rfind('/').map_or(0, |at| at + 1);
            let name = &entry.path.as_bytes()[name_start..];
            // Look the name up in the chain of its bucket, a few links at a time.
            let found = match self.layer_search(index, parent, name, limits.insert_links - links) {
                Search::More => return LayerReply::Resolving,
                Search::Done(found, spent) => {
                    links += spent;
                    found
                }
            };
            self.state.layers.layers[index].chain = Chain::START;
            bytes += name.len();
            done += 1;
            match self.insert_entry(index, i, &entry, parent, name_start, found, now) {
                Ok(()) => {}
                Err(reply) => return self.insert_failed(index, reply),
            }
            let layer = &mut self.state.layers.layers[index];
            layer.cursor += 1;
        }
        let layer = &mut self.state.layers.layers[index];
        layer.state = LayerState::Attached;
        let names = layer.names;
        self.state.layers.job.layer = NO_LAYER;
        LayerReply::Done { names }
    }

    /// An insertion refused: the names already in go out again, then the answer is given.
    fn insert_failed(&mut self, index: usize, reply: LayerReply) -> LayerReply {
        let layer = &mut self.state.layers.layers[index];
        let (status, entry) = match reply {
            LayerReply::Entry { status, entry } => (status, entry),
            LayerReply::Refused { status } => (status, NO_ENTRY_NUMBER),
            _ => unreachable!("a refusal"),
        };
        layer.failure = Some((status, entry));
        layer.state = LayerState::RollingBack;
        // `cursor` is the first entry not inserted; the detach starts below it.
        LayerReply::Resolving
    }

    // ---- Search of a name in the chain of its bucket -------------------------------------

    fn layer_search(&mut self, index: usize, parent: Token, name: &[u8], budget: usize) -> Search {
        let bucket = name_bucket(parent, name) as u16;
        let chain = self.state.layers.layers[index].chain;
        let (mut link, mut spent) = if chain.started
            && chain.bucket == bucket
            && self.stamp(bucket as usize) == chain.stamp
        {
            (chain.link, 0)
        } else {
            (self.name_head(parent, name), 0)
        };
        let stamp = self.stamp(bucket as usize);
        while link != NONE {
            if spent == budget {
                self.state.layers.layers[index].chain = Chain {
                    started: true,
                    bucket,
                    stamp,
                    link,
                };
                return Search::More;
            }
            spent += 1;
            if let Some((found, token)) = self.entry(parent, link as usize)
                && found == name
            {
                return Search::Done(Some(token), spent);
            }
            link = self.name_next(link);
        }
        Search::Done(None, spent)
    }

    fn pop_slot(&mut self) -> usize {
        let layers = &mut self.state.layers;
        layers.slot_len -= 1;
        SLOT_BASE + layers.slot_free[layers.slot_len] as usize
    }

    fn push_slot(&mut self, b: usize) {
        let layers = &mut self.state.layers;
        layers.slot_free[layers.slot_len] = (b - SLOT_BASE) as u16;
        layers.slot_len += 1;
    }

    /// Takes in one entry whose name was looked up. The error is the refusal to answer.
    #[allow(clippy::too_many_arguments)]
    fn insert_entry(
        &mut self,
        index: usize,
        i: usize,
        entry: &rootfs::Entry<'_>,
        parent: Token,
        name_start: usize,
        found: Option<Token>,
        now: proto_fs::Timestamp,
    ) -> Result<(), LayerReply> {
        let number = i as u32;
        if self.state.layers.slot_len == 0 {
            return Err(LayerReply::Refused {
                status: proto_fs::NO_SPACE,
            });
        }
        let name_length = (entry.path.len() - name_start) as u8;
        let layer_time = self.state.layers.layers[index].time;
        let made = i64::try_from(layer_time)
            .ok()
            .filter(|&seconds| seconds > 0)
            .and_then(|seconds| proto_fs::Timestamp::new(seconds, 0).ok())
            .unwrap_or(now);
        let name_offset = {
            let base = self.layer_bytes(index).as_ptr() as usize;
            (entry.path.as_ptr() as usize - base + name_start) as u32
        };
        let (data_offset, data_length) = if entry.is_directory() {
            (0, 0)
        } else {
            let bytes = self.layer_bytes(index);
            let view = BootImage::view_as(bytes, &PACKAGE).expect("viewed by layer_mapped");
            let file = view.file(entry.file).map_err(|_| bad_layer(number))?;
            (file.offset as u32, file.data.len() as u32)
        };
        let directory = entry.is_directory();
        match found {
            Some(token) if directory => {
                // Merge into the directory that is there.
                let node = self.node(token).map_err(|_| refuse(CONFLICT, number))?;
                if node.kind != crate::DIR {
                    return Err(refuse(CONFLICT, number));
                }
                let owned = (node.boot != NONE
                    && (RESERVE_BASE..BOOT_SPACE).contains(&(node.boot as usize))
                    && token.slot == 5 + node.boot)
                    .then_some(node.boot);
                let b = self.pop_slot();
                if let Some(r) = owned {
                    self.state.layers.reserve[r as usize - RESERVE_BASE].owners += 1;
                }
                self.state.originals[4 + b] = Original {
                    parent,
                    node: token,
                    hidden: true,
                    cookie: 0,
                };
                self.layer_occupy(
                    index,
                    i,
                    b,
                    Place {
                        layer: index as u8,
                        kind: PLACE_DIR,
                        name_length,
                        first: owned.unwrap_or(NONE),
                        name_offset,
                        data_offset: 0,
                        data_length: 0,
                    },
                );
                Ok(())
            }
            Some(_) => Err(refuse(CONFLICT, number)),
            None if directory => {
                if self.state.layers.reserve_len == 0 {
                    return Err(LayerReply::Refused {
                        status: proto_fs::NO_SPACE,
                    });
                }
                let cookie = self
                    .next_directory_cookie()
                    .map_err(|code| LayerReply::Refused { status: code })?;
                let r = {
                    let layers = &mut self.state.layers;
                    layers.reserve_len -= 1;
                    layers.reserve_free[layers.reserve_len] as usize
                };
                let name = &entry.path.as_bytes()[name_start..];
                let reserve = &mut self.state.layers.reserve[r];
                reserve.name[..name.len()].copy_from_slice(name);
                reserve.length = name_length;
                reserve.owners = 1;
                reserve.queued = false;
                let rb = RESERVE_BASE + r;
                let generation = self.state.nodes[5 + rb].generation + 1;
                self.state.nodes[5 + rb] = Node {
                    generation,
                    kind: crate::DIR,
                    mode: entry.mode & 0o7777,
                    links: 2,
                    parent,
                    times: [made; 3],
                    boot: rb as u16,
                    name_entry: (4 + rb) as u16,
                    ..Node::EMPTY
                };
                self.state.boot_files += 1;
                let token = Token {
                    slot: (5 + rb) as u16,
                    generation,
                };
                self.state.originals[4 + rb] = Original {
                    parent,
                    node: token,
                    hidden: false,
                    cookie,
                };
                self.publish(4 + rb);
                let b = self.pop_slot();
                self.state.originals[4 + b] = Original {
                    parent,
                    node: token,
                    hidden: true,
                    cookie: 0,
                };
                self.layer_occupy(
                    index,
                    i,
                    b,
                    Place {
                        layer: index as u8,
                        kind: PLACE_DIR,
                        name_length,
                        first: rb as u16,
                        name_offset,
                        data_offset: 0,
                        data_length: 0,
                    },
                );
                Ok(())
            }
            None => {
                let cookie = self
                    .next_directory_cookie()
                    .map_err(|code| LayerReply::Refused { status: code })?;
                let first_entry = self.state.layers.job.first_of_file[entry.file as usize];
                let b = self.pop_slot();
                let canonical = if first_entry as usize == i {
                    b
                } else {
                    self.state.layers.entry_place[index][first_entry as usize] as usize
                };
                self.layer_occupy(
                    index,
                    i,
                    b,
                    Place {
                        layer: index as u8,
                        kind: PLACE_FILE,
                        name_length,
                        first: canonical as u16,
                        name_offset,
                        data_offset,
                        data_length,
                    },
                );
                if canonical == b {
                    let generation = self.state.nodes[5 + b].generation + 1;
                    let (kind, mode) = if entry.is_symlink() {
                        (SYMLINK, 0o777)
                    } else {
                        (crate::REG, entry.mode & 0o7777)
                    };
                    self.state.nodes[5 + b] = Node {
                        generation,
                        kind,
                        mode,
                        links: 1,
                        parent,
                        length: u64::from(data_length),
                        boot_visible_length: u64::from(data_length),
                        times: [made; 3],
                        boot: b as u16,
                        ..Node::EMPTY
                    };
                    self.state.boot_files += 1;
                    self.state.boot_blocks += u64::from(data_length).div_ceil(PAGE as u64);
                } else {
                    self.state.nodes[5 + canonical].links += 1;
                }
                let node = &self.state.nodes[5 + canonical];
                self.state.originals[4 + b] = Original {
                    parent,
                    node: Token {
                        slot: (5 + canonical) as u16,
                        generation: node.generation,
                    },
                    hidden: false,
                    cookie,
                };
                self.publish(4 + b);
                Ok(())
            }
        }
    }

    /// Records that entry `i` of the layer holds place `b`.
    fn layer_occupy(&mut self, index: usize, i: usize, b: usize, place: Place) {
        let layers = &mut self.state.layers;
        layers.places[b - SLOT_BASE] = place;
        layers.entry_place[index][i] = b as u16;
        let layer = &mut layers.layers[index];
        layer.occupied += 1;
        layer.names += 1;
    }

    // ---- Detach and rollback --------------------------------------------------------------

    /// Begins a detach of layer `number`.
    pub fn layer_begin_detach(&mut self, number: u32) -> Result<(), u32> {
        let index = self.layer_index(number).ok_or(proto_fs::NO_ENTRY)?;
        if self.state.layers.layers[index].image {
            return Err(PERMISSION);
        }
        if self.state.layers.layers[index].state != LayerState::Attached {
            return Err(if self.state.layers.job.layer == NO_LAYER {
                proto_fs::NO_ENTRY
            } else {
                BUSY
            });
        }
        if self.state.layers.job.layer != NO_LAYER {
            return Err(BUSY);
        }
        let layer = &mut self.state.layers.layers[index];
        layer.state = LayerState::Detaching;
        layer.cursor = layer.count;
        layer.failure = None;
        self.state.layers.job.layer = index as u8;
        Ok(())
    }

    /// Takes names out, from the last entry of the walk down. The rollback of an attach and the
    /// detach are the same work.
    fn detach_step(&mut self, index: usize, limits: &Limits) -> LayerReply {
        let mut bytes = 0;
        let mut done = 0;
        let rolling = self.state.layers.layers[index].state == LayerState::RollingBack;
        loop {
            let cursor = self.state.layers.layers[index].cursor as usize;
            if cursor == 0 {
                break;
            }
            if done >= limits.detach_entries || bytes >= limits.detach_bytes {
                return LayerReply::Resolving;
            }
            let i = cursor - 1;
            self.state.layers.layers[index].cursor = i as u16;
            let b = self.state.layers.entry_place[index][i];
            if b == NONE {
                continue;
            }
            self.state.layers.entry_place[index][i] = NONE;
            let place = self.state.layers.places[b as usize - SLOT_BASE];
            bytes += usize::from(place.name_length);
            done += 1;
            self.layer_release_entry(index, b as usize, place);
        }
        let layer = &mut self.state.layers.layers[index];
        let names = layer.names;
        let failure = layer.failure;
        layer.names = 0;
        self.layer_end(index);
        match failure {
            Some((status, entry)) if rolling => match status {
                CONFLICT | BAD_LAYER | BAD_MODE => refuse(status, entry),
                _ => LayerReply::Refused { status },
            },
            _ => LayerReply::Done { names },
        }
    }

    /// Takes the entry in place `b` out of the tree.
    fn layer_release_entry(&mut self, index: usize, b: usize, place: Place) {
        match place.kind {
            PLACE_FILE => {
                self.unpublish(4 + b);
                self.state.originals[4 + b] = Original::EMPTY;
                let canonical = place.first as usize;
                let node = &mut self.state.nodes[5 + canonical];
                node.links = node.links.saturating_sub(1);
                if canonical != b {
                    self.layer_free_slot(index, b);
                } else if !node.retained() {
                    self.layer_free_node(canonical);
                    self.layer_free_slot(index, b);
                }
                // Otherwise the place waits for the last holder: `collect` frees it.
            }
            _ => {
                self.state.originals[4 + b] = Original::EMPTY;
                if place.first != NONE {
                    let r = place.first as usize - RESERVE_BASE;
                    let reserve = &mut self.state.layers.reserve[r];
                    reserve.owners = reserve.owners.saturating_sub(1);
                    if reserve.owners == 0 {
                        self.layer_reserve_release(r);
                    }
                }
                self.layer_free_slot(index, b);
            }
        }
    }

    fn layer_free_slot(&mut self, index: usize, b: usize) {
        self.state.layers.places[b - SLOT_BASE] = Place::FREE;
        self.push_slot(b);
        let layer = &mut self.state.layers.layers[index];
        layer.occupied -= 1;
        self.layer_check_released(index);
    }

    /// The node of place `b` is gone: its place of the node table is empty, with the
    /// generation kept so that no token of the old file names the next.
    fn layer_free_node(&mut self, b: usize) {
        let node = &mut self.state.nodes[5 + b];
        let blocks = node.boot_visible_length.div_ceil(PAGE as u64);
        let regular = node.kind == crate::REG || node.kind == SYMLINK;
        *node = Node {
            generation: node.generation,
            ..Node::EMPTY
        };
        self.state.boot_files -= 1;
        if regular {
            self.state.boot_blocks -= blocks;
        }
    }

    /// The reserve directory `r` has no owner. With no name in it the directory goes; with
    /// names of users it stays until the last one leaves.
    fn layer_reserve_release(&mut self, r: usize) {
        let rb = RESERVE_BASE + r;
        let node = self.state.nodes[5 + rb];
        if node.kind != crate::DIR || node.links == 0 {
            return;
        }
        if node.names != 0 {
            return;
        }
        self.unpublish(4 + rb);
        self.state.originals[4 + rb] = Original::EMPTY;
        self.state.nodes[5 + rb].links = 0;
        if !self.state.nodes[5 + rb].retained() {
            self.layer_free_reserve(r);
        }
    }

    fn layer_free_reserve(&mut self, r: usize) {
        let rb = RESERVE_BASE + r;
        self.layer_free_node(rb);
        let layers = &mut self.state.layers;
        layers.reserve[r] = ReserveDir::FREE;
        layers.reserve_free[layers.reserve_len] = r as u16;
        layers.reserve_len += 1;
    }

    /// The node in place `slot - 5` of the image is no longer held: frees its place if it was
    /// kept only for its holders. Called by `collect` for a node without links.
    pub(crate) fn layer_collect(&mut self, token: Token) {
        let b = token.slot as usize - 5;
        let node = self.state.nodes[token.slot as usize];
        if node.links != 0 || node.retained() || node.kind == 0 {
            return;
        }
        if b >= RESERVE_BASE {
            self.layer_free_reserve(b - RESERVE_BASE);
        } else {
            let place = self.state.layers.places[b - SLOT_BASE];
            if place.layer == NO_LAYER {
                return;
            }
            self.layer_free_node(b);
            self.layer_free_slot(place.layer as usize, b);
        }
    }

    /// A name left directory `dir`: a reserve directory without owner and names is examined
    /// when the service next has time (a name may be on its way to another directory).
    pub(crate) fn layer_name_left(&mut self, dir: Token) {
        let b = dir.slot as usize;
        if !(5 + RESERVE_BASE..5 + BOOT_SPACE).contains(&b) {
            return;
        }
        let r = b - 5 - RESERVE_BASE;
        let layers = &mut self.state.layers;
        if layers.reserve[r].owners != 0 || layers.reserve[r].queued {
            return;
        }
        layers.reserve[r].queued = true;
        let tail = (layers.queue_head + layers.queue_len) % LAYER_DIRS;
        layers.queue[tail] = r as u8;
        layers.queue_len += 1;
    }

    /// Work the service has kept for a quiet moment: directories of the reserve that have lost
    /// their last name, and the work of a layer whose client left. True while there is more.
    pub fn layer_maintain(&mut self, now: proto_fs::Timestamp, limits: &Limits) -> bool {
        let job = self.state.layers.job.layer;
        if job != NO_LAYER && self.state.layers.layers[job as usize].orphan {
            // The client is gone: roll back an attach, finish a detach.
            let _ = self.layer_work_step(job as usize, now, limits);
            return true;
        }
        let layers = &mut self.state.layers;
        if layers.queue_len == 0 {
            return false;
        }
        let r = layers.queue[layers.queue_head] as usize;
        layers.queue_head = (layers.queue_head + 1) % LAYER_DIRS;
        layers.queue_len -= 1;
        layers.reserve[r].queued = false;
        if layers.reserve[r].owners == 0 {
            self.layer_reserve_release(r);
        }
        self.state.layers.queue_len != 0
    }

    /// Whether `layer_maintain` has work.
    pub fn layer_work(&self) -> bool {
        let job = self.state.layers.job.layer;
        self.state.layers.queue_len != 0
            || job != NO_LAYER && self.state.layers.layers[job as usize].orphan
    }

    /// The client of the layer session left. A job of theirs ends by itself: a mapping that is
    /// under way is given back when it arrives, a check is dropped, an insertion is rolled
    /// back, a detach is finished.
    pub fn layer_client_gone(&mut self) {
        let job = self.state.layers.job.layer;
        if job == NO_LAYER {
            return;
        }
        let index = job as usize;
        let layers = &mut self.state.layers;
        layers.layers[index].orphan = true;
        match layers.layers[index].state {
            LayerState::Checking => {
                layers.layers[index].failure = Some((CONFLICT, NO_ENTRY_NUMBER));
                self.layer_end(index);
            }
            LayerState::Inserting => {
                layers.layers[index].failure = Some((CONFLICT, NO_ENTRY_NUMBER));
                layers.layers[index].state = LayerState::RollingBack;
            }
            _ => {}
        }
    }

    /// Whether the job of layer `index` has no one to answer.
    pub fn layer_orphan(&self, index: usize) -> bool {
        self.state.layers.layers[index].orphan
    }

    // ---- Layers of the boot image -----------------------------------------------------------

    /// Attaches a package file the boot image holds as layer `number` of the image, in one go.
    /// `bytes` lives as long as the service. The error says what is wrong.
    pub fn layer_attach_image(
        &mut self,
        number: u32,
        bytes: &'static [u8],
        now: proto_fs::Timestamp,
    ) -> Result<u32, LayerReply> {
        let index = self.layer_begin_attach(number, true).map_err(refused)?;
        if let Err(reply) = self.layer_mapped(index, bytes.as_ptr(), bytes.len()) {
            self.layer_unmapped(index);
            return Err(reply);
        }
        loop {
            match self.layer_step(number, now, &Limits::WHOLE) {
                LayerReply::Resolving => {}
                LayerReply::Done { names } => return Ok(names),
                failure => {
                    // The rollback ran in the same step; the layer holds no place.
                    while let Some(done) = self.layer_next_released() {
                        self.layer_unmapped(done.index);
                    }
                    return Err(failure);
                }
            }
        }
    }

    /// The filesystem of a layer's node refuses the change of its name or attributes.
    pub(crate) fn layer_read_only(&self, token: Token) -> Result<(), u32> {
        if self.is_layer_node(token) {
            Err(READ_ONLY_FILESYSTEM)
        } else {
            Ok(())
        }
    }
}

enum Search {
    /// The name looked for, or none, and the links followed.
    Done(Option<Token>, usize),
    /// The links are spent; the next step goes on.
    More,
}
