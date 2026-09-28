// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use super::*;
use crate::signals::{
    ACTION, DEFAULT, MASK, PENDING, READY as ATTACHED, SEND, SigAction, TAKE, WAIT,
};

pub(super) struct Waiting {
    pub(super) nonce: u64,
    set: posix_signals::SigSet,
    token: sys::Token,
}
impl Registry {
    pub(super) fn signal_wait_begin(&mut self, caller: usize, words: [u64; 8], token: sys::Token) {
        if let Some(wait) = self.entry_mut(caller).signal_waiting.as_mut() {
            if wait.nonce == words[2] {
                wait.token = token;
                return;
            }
            let answer = self.cache(caller, words[2], Err(EBUSY), WAIT);
            respond(token, answer);
            return;
        }
        let set = match posix_signals::mask(words[3]) {
            Ok(set) if set & !self.entry(caller).signal.mask == 0 => set,
            _ => {
                let answer = self.cache(caller, words[2], Err(EINVAL), WAIT);
                respond(token, answer);
                return;
            }
        };
        self.entry_mut(caller).signal_waiting = Some(Waiting {
            nonce: words[2],
            set,
            token,
        });
        self.signal_accept_wait(caller);
    }
    fn signal_accept_wait(&mut self, index: usize) -> bool {
        let Some(wait) = self.entry(index).signal_waiting.as_ref() else {
            return false;
        };
        let set = wait.set;
        let Some(signal) = self
            .entry_mut(index)
            .signal
            .accept(set)
            .expect("validated signal wait set")
        else {
            return false;
        };
        let wait = self
            .entry_mut(index)
            .signal_waiting
            .take()
            .expect("accepted signal wait");
        let mut result = [0; 7];
        result[0] = signal as u64;
        result[2..].copy_from_slice(&posix_types::SigInfo::thread(signal).words());
        let answer = self.cache_words(index, wait.nonce, Ok(result), WAIT);
        respond(wait.token, answer);
        true
    }

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
    ) -> Result<[u64; 7], i32> {
        let pair = |value, extra| [value, extra, 0, 0, 0, 0, 0];
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
                let action = posix_signals::action_words(old);
                Ok([action[0], action[1], action[2], 0, 0, 0, 0])
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
                Ok(pair(old, 0))
            }
            SEND => {
                let signal = words[4] as i32;
                if signal != 0 {
                    posix_signals::bit(signal).map_err(|_| EINVAL)?;
                }
                let index = self.find(words[3])?;
                // Inactive joinable IDs retain their lifetime and accept signal 0.
                if signal == 0 || self.entry(index).phase != Phase::Live {
                    return Ok(pair(0, 0));
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
                if self.signal_accept_wait(index) {
                    // Acceptance is committed. No fallible native request may
                    // roll the consumed signal back into the pending set.
                    return Ok(pair(0, 0));
                }
                if let Err(code) = self.signal_wake(index) {
                    self.entry_mut(index).signal = before;
                    return Err(code);
                }
                Ok(pair(0, 0))
            }
            PENDING => Ok(pair(self.entry(caller).signal.pending(), 0)),
            TAKE => {
                let entry = self.entries[caller].as_mut().expect("signal caller");
                Ok(entry
                    .signal
                    .take(&mut self.signals)
                    .map_or(pair(0, 0), |(signal, action)| {
                        let mut snapshot = pair(
                            signal as u64 | ((action.flags as u64) << 32),
                            action.handler,
                        );
                        snapshot[2..]
                            .copy_from_slice(&posix_types::SigInfo::thread(signal).words());
                        snapshot
                    }))
            }
            ATTACHED => {
                self.entry_mut(caller).signal.ready = true;
                self.signal_wake(caller)?;
                Ok(pair(0, 0))
            }
            _ => Err(EINVAL),
        }
    }
}
