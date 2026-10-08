// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exercise the kernel's actual intrusive metadata with resident host objects.

use core::ptr::NonNull;

mod process {
    use super::*;
    pub struct Process {
        pub alive: bool,
        pub layer_head: Option<NonNull<crate::thread::Thread>>,
    }
    pub fn check_alive(p: NonNull<Process>) -> Result<(), abi::Error> {
        if unsafe { p.as_ref() }.alive {
            Ok(())
        } else {
            Err(abi::Error::BadState)
        }
    }
    pub(crate) use crate::actual_layers as layers;
}
use process::{Process, check_alive};
#[path = "../../kernel/src/process/layers.rs"]
pub mod actual_layers;

mod thread {
    use super::*;
    pub struct Thread {
        pub upcall: kcore::upcall::State,
        pub layer: Option<process::layers::LayerLinks>,
        pub owner: NonNull<process::Process>,
    }
    impl Thread {
        pub fn process(&self) -> NonNull<process::Process> {
            self.owner
        }
    }
}
use process::layers::{OBSERVER, PRIMARY, ending, select, set_role};

#[expect(
    clippy::vec_box,
    reason = "Stable addresses are required by the actual intrusive links."
)]
struct Resident {
    process: Box<process::Process>,
    threads: Vec<Box<thread::Thread>>,
}
impl Resident {
    fn new(count: usize) -> Self {
        let mut process = Box::new(process::Process {
            alive: true,
            layer_head: None,
        });
        let owner = NonNull::from(&mut *process);
        let threads = (0..count)
            .map(|_| {
                let mut state = kcore::upcall::State::new();
                state.bind(0x1000).unwrap();
                state.bind_observer(0x2000, 0x3000).unwrap();
                state.control(1).unwrap();
                state.control(6).unwrap();
                Box::new(thread::Thread {
                    upcall: state,
                    layer: None,
                    owner,
                })
            })
            .collect();
        Self { process, threads }
    }
    fn thread(&mut self, index: usize) -> NonNull<thread::Thread> {
        NonNull::from(&mut *self.threads[index])
    }
    fn process(&mut self) -> NonNull<process::Process> {
        NonNull::from(&mut *self.process)
    }
}

#[test]
fn arbitrary_handlers_are_unpublished_until_current_ready() {
    let mut resident = Resident::new(1);
    let p = resident.process();
    assert!(unsafe { select(p, true) }.is_err());
    assert_eq!(
        core::mem::size_of::<Option<process::layers::LayerLinks>>(),
        24
    );
}

#[test]
fn both_roles_share_one_node_and_partial_unbind_preserves_survivor() {
    let mut resident = Resident::new(1);
    let t = resident.thread(0);
    let p = resident.process();
    unsafe {
        set_role(t, PRIMARY, true).unwrap();
        set_role(t, OBSERVER, true).unwrap();
        assert!(select(p, true).unwrap().observer);
        assert!(select(p, true).unwrap().observer);
        set_role(t, PRIMARY, false).unwrap();
        (*t.as_ptr()).upcall.bind(0).unwrap();
        assert!(select(p, true).unwrap().observer);
        set_role(t, OBSERVER, false).unwrap();
        assert!(select(p, true).is_err());
        assert!((*t.as_ptr()).layer.is_none());
    }
}

#[test]
fn observer_unbind_selects_same_head_primary_for_retained_page_pending() {
    let mut resident = Resident::new(1);
    let t = resident.thread(0);
    unsafe {
        set_role(t, PRIMARY, true).unwrap();
        set_role(t, OBSERVER, true).unwrap();
        (*t.as_ptr()).upcall.request_observer().unwrap();
        (*t.as_ptr()).upcall.bind_observer(0, 0).unwrap();
        let next = set_role(t, OBSERVER, false).unwrap().unwrap();
        assert_eq!(next.thread, t);
        assert!(!next.observer);
        (*next.thread.as_ptr()).upcall.request().unwrap();
        assert_eq!(
            (*t.as_ptr())
                .upcall
                .prepare_with_tls(0x4000, 0, 0, false)
                .unwrap()
                .pc,
            0x1000
        );
    }
}

#[test]
fn round_robin_and_head_middle_last_end_leave_no_dangling_membership() {
    let mut resident = Resident::new(3);
    let a = resident.thread(0);
    let b = resident.thread(1);
    let c = resident.thread(2);
    let p = resident.process();
    unsafe {
        set_role(a, PRIMARY, true).unwrap();
        set_role(b, OBSERVER, true).unwrap();
        set_role(c, PRIMARY, true).unwrap();
        for expected in [a, b, c, a] {
            assert_eq!(select(p, true).unwrap().thread, expected);
        }
        assert_eq!(ending(a).unwrap().thread, b);
        assert_eq!(ending(c).unwrap().thread, b);
        assert!(select(p, true).unwrap().observer);
        assert!(ending(b).is_none());
        assert!(select(p, true).is_err());
        for t in [a, b, c] {
            assert!((*t.as_ptr()).layer.is_none());
        }
    }
}

#[test]
fn ended_process_unlinks_without_forwarding_or_new_publication() {
    let mut resident = Resident::new(2);
    let a = resident.thread(0);
    let b = resident.thread(1);
    unsafe {
        set_role(a, PRIMARY, true).unwrap();
        set_role(b, OBSERVER, true).unwrap();
    }
    resident.process.alive = false;
    unsafe {
        assert!(ending(a).is_none());
        assert!(set_role(a, PRIMARY, true).is_err());
        assert!(select(resident.process(), true).is_err());
        assert!(ending(b).is_none());
    }
    assert!(resident.process.layer_head.is_none());
}

#[test]
fn missing_handler_refusal_preserves_existing_role_and_head() {
    let mut resident = Resident::new(1);
    let t = resident.thread(0);
    let p = resident.process();
    unsafe {
        set_role(t, PRIMARY, true).unwrap();
        (*t.as_ptr()).upcall.bind_observer(0, 0).unwrap();
        assert!(set_role(t, OBSERVER, true).is_err());
        let selected = select(p, true).unwrap();
        assert_eq!(selected.thread, t);
        assert!(!selected.observer);
    }
}
