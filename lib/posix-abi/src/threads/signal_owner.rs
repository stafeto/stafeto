// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use super::*;
use crate::signals::{ACTION, DEFAULT, MASK, PENDING, READY as ATTACHED, SEND, SigAction, TAKE};

impl Registry {
    fn signal_wake(&self, index: usize) -> Result<(), i32> {
        let entry = self.entry(index);
        if entry.phase == Phase::Live && entry.signal.deliverable() {
            rt::sys::thread_upcall_request(entry.native.as_ref().ok_or(ESRCH)?).map_err(|_| EIO)?;
        }
        Ok(())
    }
    pub(super) fn signal_perform(
        &mut self,
        caller: usize,
        words: [u64; 8],
    ) -> Result<(u64, u64), i32> {
        match words[0] {
            ACTION => {
                let signal = words[3] as i32;
                let old = if words[4] == 0 {
                    self.signals.get(signal)
                } else {
                    self.signals.replace(
                        signal,
                        SigAction {
                            handler: words[5],
                            mask: words[6],
                            flags: words[7] as i32,
                        },
                    )
                }
                .map_err(|_| EINVAL)?;
                if words[4] != 0 && self.signals.ignored(signal) {
                    for entry in self.entries.iter_mut().flatten() {
                        entry.signal.discard(signal);
                    }
                }
                Ok((old.handler, posix_signals::packed(old)))
            }
            MASK => {
                let before = self.entry(caller).signal;
                let set = (words[4] != 0).then_some(words[5]);
                let old = self
                    .entry_mut(caller)
                    .signal
                    .change_mask(words[3] as i32, set)
                    .map_err(|_| EINVAL)?;
                if set.is_some()
                    && let Err(code) = self.signal_wake(caller)
                {
                    self.entry_mut(caller).signal = before;
                    return Err(code);
                }
                Ok((old, 0))
            }
            SEND => {
                let signal = words[4] as i32;
                if signal != 0 {
                    posix_signals::bit(signal).map_err(|_| EINVAL)?;
                }
                let index = self.find(words[3])?;
                // Inactive joinable IDs retain their lifetime and accept signal 0.
                if signal == 0 || self.entry(index).phase != Phase::Live {
                    return Ok((0, 0));
                }
                let action = self.signals.get(signal).map_err(|_| EINVAL)?;
                if signal == SIGCONT
                    || (action.handler == DEFAULT
                        && matches!(
                            posix_signals::default_action(signal),
                            posix_signals::DefaultAction::Stop
                        ))
                {
                    return Err(ENOSYS);
                }
                let before = self.entry(index).signal;
                let entry = self.entries[index].as_mut().expect("signal target");
                entry
                    .signal
                    .generate(signal, &self.signals)
                    .map_err(|_| EINVAL)?;
                if let Err(code) = self.signal_wake(index) {
                    self.entry_mut(index).signal = before;
                    return Err(code);
                }
                Ok((0, 0))
            }
            PENDING => Ok((self.entry(caller).signal.pending(), 0)),
            TAKE => {
                let entry = self.entries[caller].as_mut().expect("signal caller");
                Ok(entry
                    .signal
                    .take(&mut self.signals)
                    .map_or((0, 0), |(signal, action)| {
                        (
                            signal as u64 | ((action.flags as u64) << 32),
                            action.handler,
                        )
                    }))
            }
            ATTACHED => {
                self.entry_mut(caller).signal.ready = true;
                self.signal_wake(caller)?;
                Ok((0, 0))
            }
            _ => Err(EINVAL),
        }
    }
}
