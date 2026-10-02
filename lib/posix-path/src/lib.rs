// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Byte-oriented path state for the current single-process POSIX port.
//! The RAM namespace still lacks symbolic links and treats dot segments
//! lexically; a full namespace service must resolve each component.

#![no_std]

pub const MAX_PATH: usize = proto_fs::MAX_PATH;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathError {
    Empty,
    TooLong,
    Invalid,
}

pub struct PathState {
    cwd: [u8; MAX_PATH + 1],
    length: usize,
}

impl Default for PathState {
    fn default() -> Self {
        Self::new()
    }
}

impl PathState {
    pub const fn new() -> Self {
        let mut cwd = [0; MAX_PATH + 1];
        cwd[0] = b'/';
        Self { cwd, length: 1 }
    }

    pub fn cwd(&self) -> &[u8] {
        &self.cwd[..self.length]
    }

    pub fn resolve(&self, path: &[u8], out: &mut [u8; MAX_PATH + 1]) -> Result<usize, PathError> {
        if path.is_empty() {
            return Err(PathError::Empty);
        }
        if path.contains(&0) {
            return Err(PathError::Invalid);
        }
        let mut used = if path[0] == b'/' {
            out[0] = b'/';
            1
        } else {
            out[..self.length].copy_from_slice(self.cwd());
            self.length
        };
        for part in path.split(|byte| *byte == b'/') {
            if part.is_empty() || part == b"." {
                continue;
            }
            if part == b".." {
                if used > 1 {
                    used = out[..used]
                        .iter()
                        .rposition(|byte| *byte == b'/')
                        .unwrap_or(0)
                        .max(1);
                }
                continue;
            }
            let separator = usize::from(used > 1);
            if used + separator + part.len() > MAX_PATH {
                return Err(PathError::TooLong);
            }
            if separator != 0 {
                out[used] = b'/';
                used += 1;
            }
            out[used..used + part.len()].copy_from_slice(part);
            used += part.len();
        }
        out[used] = 0;
        Ok(used)
    }

    /// Set a directory after its existence and type have been checked.
    pub fn set_cwd(&mut self, path: &[u8]) -> Result<(), PathError> {
        let mut resolved = [0; MAX_PATH + 1];
        let length = self.resolve(path, &mut resolved)?;
        self.cwd[..=length].copy_from_slice(&resolved[..=length]);
        self.length = length;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved(state: &PathState, path: &[u8]) -> Result<([u8; MAX_PATH + 1], usize), PathError> {
        let mut out = [0; MAX_PATH + 1];
        let length = state.resolve(path, &mut out)?;
        Ok((out, length))
    }

    #[test]
    fn relative_paths_follow_the_current_directory() {
        let mut state = PathState::new();
        state.set_cwd(b"/etc").unwrap();
        let (out, n) = resolved(&state, b"./motd").unwrap();
        assert_eq!(&out[..n], b"/etc/motd");
        assert_eq!(out[n], 0);
        let (out, n) = resolved(&state, b"../tmp//probe").unwrap();
        assert_eq!(&out[..n], b"/tmp/probe");
        assert_eq!(state.cwd(), b"/etc");
    }

    #[test]
    fn root_and_parent_segments_stay_within_root() {
        let mut state = PathState::new();
        state.set_cwd(b"/tmp").unwrap();
        for path in [
            b"/".as_slice(),
            b"../../".as_slice(),
            b"/etc/../".as_slice(),
        ] {
            let (out, n) = resolved(&state, path).unwrap();
            assert_eq!(&out[..n], b"/");
        }
    }

    #[test]
    fn rejects_empty_nul_and_overlong_paths() {
        let state = PathState::new();
        let mut out = [0; MAX_PATH + 1];
        assert_eq!(state.resolve(b"", &mut out), Err(PathError::Empty));
        assert_eq!(state.resolve(b"/a\0b", &mut out), Err(PathError::Invalid));
        assert_eq!(
            state.resolve(&[b'a'; MAX_PATH], &mut out),
            Err(PathError::TooLong)
        );
        let length = state.resolve(&[b'a'; MAX_PATH - 1], &mut out).unwrap();
        assert_eq!(length, MAX_PATH);
        assert_eq!(out[length], 0);
    }

    #[test]
    fn preserves_filename_bytes_outside_utf8() {
        let state = PathState::new();
        let (out, n) = resolved(&state, b"/\xff").unwrap();
        assert_eq!(&out[..n], b"/\xff");
    }
}
