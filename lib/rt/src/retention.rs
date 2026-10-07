// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Ownership transitions for retained service resources.

/// Revoke in place; ordinary services release their slot after the callback.
pub fn revoke<T>(slot: &mut Option<T>, retained: bool, mut gone: impl FnMut(&mut T)) {
    if let Some(owner) = slot.as_mut() {
        gone(owner);
    }
    if !retained {
        *slot = None;
    }
}

/// A colliding label is refused while the old exact slot remains occupied.
pub fn collision<T>(slot: &mut Option<T>, retained: bool, gone: impl FnMut(&mut T)) -> bool {
    revoke(slot, retained, gone);
    retained
}

/// A successful close disarms exactly one owner; errors keep the original field.
pub fn close<T, E>(
    owner: &mut Option<T>,
    call: impl FnOnce(&T) -> Result<(), E>,
    disarm: impl FnOnce(T),
) -> Result<(), E> {
    let Some(handle) = owner.as_ref() else {
        return Ok(());
    };
    call(handle)?;
    disarm(owner.take().expect("successfully closed owner"));
    Ok(())
}

/// One existing mapped resource retains its exact memory owner across errors.
pub struct Window<T> {
    pub owner: u64,
    pub memory: Option<T>,
    pub length: u64,
    pub mapped: bool,
}
impl<T> Window<T> {
    /// One unmap or one close per visit. Failed calls preserve custody.
    pub fn step<E>(
        &mut self,
        unmap: impl FnOnce(u64) -> Result<(), E>,
        close: impl FnOnce(&mut Option<T>) -> Result<(), E>,
    ) -> Result<bool, E> {
        if self.mapped {
            unmap(self.length)?;
            self.mapped = false;
            return Ok(false);
        }
        close(&mut self.memory)?;
        Ok(self.memory.is_none())
    }
}

/// Retry one continuation step only after a distinct FIFO handoff step.
pub fn continuations(mut step: impl FnMut() -> bool, mut handoff: impl FnMut()) {
    while step() {
        handoff();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    struct Owner<'a>(u64, &'a Cell<usize>);
    impl Drop for Owner<'_> {
        fn drop(&mut self) {
            self.1.set(self.1.get() + 1);
        }
    }

    #[test]
    fn repeated_revocation_and_collision_preserve_exact_slot_until_terminal() {
        let drops = Cell::new(0);
        let mut slot = Some((0x8000_0000_0000_0042u64, false, Owner(71, &drops)));
        for _ in 0..20 {
            revoke(&mut slot, true, |old| old.1 = true);
            let old = slot.as_ref().unwrap();
            assert_eq!(old.0, 0x8000_0000_0000_0042u64);
            assert!(old.1);
            assert_eq!(old.2.0, 71);
            assert_eq!(drops.get(), 0);
        }
        slot = None;
        assert!(slot.is_none());
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn saturated_retained_slots_refuse_collisions_and_preserve_all_320_owners() {
        let drops = Cell::new(0);
        let mut slots = core::array::from_fn::<_, 320, _>(|i| {
            Some((i as u64 + 1, false, Owner(i as u64, &drops)))
        });
        for _ in 0..3 {
            for (i, slot) in slots.iter_mut().enumerate() {
                assert!(collision(slot, true, |old| old.1 = true));
                assert_eq!(slot.as_ref().unwrap().0, i as u64 + 1);
                assert_eq!(slot.as_ref().unwrap().2.0, i as u64);
            }
            assert_eq!(slots.iter().filter(|slot| slot.is_some()).count(), 320);
            assert_eq!(drops.get(), 0);
        }
        drop(slots);
        assert_eq!(drops.get(), 320);
    }

    #[test]
    fn ordinary_revocation_releases_slot() {
        let drops = Cell::new(0);
        let mut slot = Some(Owner(71, &drops));
        revoke(&mut slot, false, |_| {});
        assert!(slot.is_none());
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn each_of_five_failed_closes_keeps_its_exact_owner() {
        let drops = Cell::new(0);
        let mut owners = core::array::from_fn::<_, 5, _>(|i| Some(Owner(i as u64, &drops)));
        for i in 0..5 {
            assert_eq!(
                close(&mut owners[i], |_| Err(19), core::mem::forget),
                Err(19)
            );
            assert_eq!(owners[i].as_ref().unwrap().0, i as u64);
            assert_eq!(drops.get(), 0);
            assert_eq!(
                close(&mut owners[i], |_| Ok::<_, u32>(()), core::mem::forget),
                Ok(())
            );
            assert!(owners[i].is_none());
            assert_eq!(owners.iter().filter(|owner| owner.is_some()).count(), 4 - i);
        }
        assert_eq!(drops.get(), 0);
    }

    #[test]
    fn failed_unmap_then_failed_close_retains_exact_memory_and_distinct_phases() {
        let drops = Cell::new(0);
        let mut window = Window {
            owner: 0x8000_0000_0000_0042u64,
            memory: Some(Owner(91, &drops)),
            length: 8192,
            mapped: true,
        };
        assert_eq!(
            window.step(
                |len| {
                    assert_eq!(len, 8192);
                    Err(7)
                },
                |_| panic!("close before unmap")
            ),
            Err(7)
        );
        assert!(window.mapped);
        assert_eq!(window.owner, 0x8000_0000_0000_0042u64);
        assert_eq!(window.memory.as_ref().unwrap().0, 91);
        assert_eq!(
            window.step(|_| Ok::<_, u32>(()), |_| panic!("two effects")),
            Ok(false)
        );
        assert!(!window.mapped);
        assert_eq!(
            window.step(
                |_| panic!("repeated unmap"),
                |owner| close(owner, |_| Err(8), core::mem::forget)
            ),
            Err(8)
        );
        assert_eq!(window.memory.as_ref().unwrap().0, 91);
        assert_eq!(
            window.step(
                |_| panic!("repeated unmap"),
                |owner| close(owner, |_| Ok::<_, u32>(()), core::mem::forget)
            ),
            Ok(true)
        );
        assert_eq!(drops.get(), 0);
    }
}

#[cfg(test)]
mod continuation_tests {
    use super::continuations;
    use std::cell::RefCell;
    #[test]
    fn retry_notify_and_fifo_yield_are_distinct_steps_until_wake_succeeds() {
        let effects = RefCell::new(std::vec::Vec::new());
        let mut attempts = 0;
        continuations(
            || {
                effects.borrow_mut().push("notify");
                attempts += 1;
                attempts < 3
            },
            || effects.borrow_mut().push("yield"),
        );
        assert_eq!(attempts, 3);
        assert_eq!(
            &*effects.borrow(),
            &["notify", "yield", "notify", "yield", "notify"]
        );
    }
}
