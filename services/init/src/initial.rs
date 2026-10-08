// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Validated initial programs retain their immutable source association.

use bootimg::exec_bindings::{self, Bindings, InitialSource};
use bootimg::{BootImage, Program};

#[derive(Clone, Copy, Debug)]
pub struct InitialProgram<'a> {
    pub program: Program<'a>,
    pub source: InitialSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Image(bootimg::Error),
    MissingBindings,
    Bindings(exec_bindings::Error),
}

pub struct Programs<'a> {
    image: BootImage<'a>,
    bindings: Bindings<'a>,
}

impl<'a> Programs<'a> {
    /// Validate the complete initial table, including init's own program.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let image = BootImage::parse(bytes).map_err(Error::Image)?;
        let metadata = image
            .files()
            .find(|file| file.name == exec_bindings::FILE)
            .ok_or(Error::MissingBindings)?;
        let bindings = Bindings::parse(metadata.data, image.count()).map_err(Error::Bindings)?;
        bindings.validate_layout(image).map_err(Error::Bindings)?;
        Ok(Self { image, bindings })
    }

    /// Resolve the exact packed artifact named by the checked service table.
    pub fn get(&self, name: &str) -> Option<InitialProgram<'a>> {
        for index in 0..self.bindings.len() {
            let source = self.bindings.entry(index);
            let file = self.image.file_at(source.artifact)?;
            if file.name == name {
                return Some(InitialProgram {
                    program: self
                        .bindings
                        .resolve(self.image, source, name.as_bytes())
                        .ok()?,
                    source,
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(include_metadata: bool, missing_row: bool) -> Vec<u8> {
        let mut raw = vec![0u8; 4100];
        raw[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, value) in [(16, 2u16), (18, 183), (52, 64), (54, 56), (56, 1)] {
            raw[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        raw[20..24].copy_from_slice(&1u32.to_le_bytes());
        for (at, value) in [
            (24, 4096u64),
            (32, 64),
            (72, 4096),
            (80, 4096),
            (96, 4),
            (104, 4096),
            (112, 4096),
        ] {
            raw[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        raw[64..68].copy_from_slice(&1u32.to_le_bytes());
        raw[68..72].copy_from_slice(&5u32.to_le_bytes());
        raw[4096..].copy_from_slice(&[1, 2, 3, 4]);
        let packed = bootimg::write::program(&bootimg::elf::program(&raw, 4096).unwrap()).unwrap();
        let rows = [
            InitialSource {
                artifact: 0,
                raw: 2,
                canonical: None,
            },
            InitialSource {
                artifact: 1,
                raw: 3,
                canonical: None,
            },
        ];
        let metadata = exec_bindings::write(&rows[..if missing_row { 1 } else { 2 }], 5).unwrap();
        bootimg::write::image(&[
            ("init", &packed),
            ("guest", &packed),
            ("init.elf", &raw),
            ("guest.elf", &raw),
            (
                if include_metadata {
                    exec_bindings::FILE
                } else {
                    "spare"
                },
                &metadata,
            ),
        ])
        .unwrap()
    }

    #[test]
    fn lookup_retains_each_exact_initial_source() {
        let bytes = image(true, false);
        let programs = Programs::parse(&bytes).unwrap();
        let own = programs.get("init").unwrap();
        let guest = programs.get("guest").unwrap();
        assert_eq!(
            own.source,
            InitialSource {
                artifact: 0,
                raw: 2,
                canonical: None
            }
        );
        assert_eq!(
            guest.source,
            InitialSource {
                artifact: 1,
                raw: 3,
                canonical: None
            }
        );
        assert_eq!(own.program.entry, guest.program.entry);
        assert!(programs.get("guest.elf").is_none());
        assert!(programs.get("missing").is_none());
    }

    #[test]
    fn missing_metadata_or_initial_coverage_refuses_the_whole_table() {
        assert!(matches!(
            Programs::parse(&image(false, false)),
            Err(Error::MissingBindings)
        ));
        assert!(matches!(
            Programs::parse(&image(true, true)),
            Err(Error::Bindings(exec_bindings::Error::Coverage))
        ));
    }
}
