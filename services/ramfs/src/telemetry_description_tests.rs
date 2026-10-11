// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use super::*;

fn source(ram: &Ram<'_>, fds: &Fds, fd: u32) -> TentativeOpen {
    ram.capture_description(fds, fd).unwrap().0
}

#[test]
fn physical_observer_keeps_detached_io_and_never_changes_references() {
    let mut ram = Ram::default();
    let mut holder = Fds::default();
    let fd = ram.open(&mut holder, "/etc/motd", READ_ONLY).unwrap();
    let target = source(&ram, &holder, fd);
    let mut controller = Fds::default();
    let witness = ram.open(&mut controller, "/etc/motd", READ_ONLY).unwrap();
    let witness = source(&ram, &controller, witness);
    let token = target.description;
    let before = ram.storage.usage(holder.root);
    assert_eq!(
        ram.telemetry_description(
            &controller,
            witness,
            u32::from(token.slot),
            token.generation
        ),
        Ok([1, 1, 1, u64::from(token.slot), token.generation])
    );
    assert!(
        ram.detach_descriptor(&mut holder, target)
            .unwrap()
            .unwrap()
            .last_fd
    );
    assert_eq!(ram.live_description(&holder, target), Err(BAD_FD));
    for _ in 0..3 {
        assert_eq!(
            ram.telemetry_description(
                &controller,
                witness,
                u32::from(token.slot),
                token.generation
            ),
            Ok([1, 1, 0, u64::from(token.slot), token.generation])
        );
    }
    assert_eq!(ram.storage.usage(holder.root), before);
    let mut byte = [0];
    assert_eq!(ram.read(&mut holder, fd, &mut byte), Ok(1));
    assert_eq!(byte, *b"s");
    ram.close(&mut holder, fd).unwrap();
    assert_eq!(
        ram.telemetry_description(
            &controller,
            witness,
            u32::from(token.slot),
            token.generation
        ),
        Ok([0; 5])
    );
    let replacement = ram.open(&mut holder, "/etc/motd", READ_ONLY).unwrap();
    let replacement = source(&ram, &holder, replacement).description;
    assert_eq!(replacement.slot, token.slot);
    assert_ne!(replacement.generation, token.generation);
    assert_eq!(
        ram.telemetry_description(
            &controller,
            witness,
            u32::from(token.slot),
            token.generation
        ),
        Ok([0; 5])
    );
    assert_eq!(
        ram.telemetry_description(&controller, witness, u32::MAX, 1),
        Ok([0; 5])
    );
    assert_eq!(
        ram.telemetry_description(&controller, witness, u32::from(replacement.slot), 0),
        Ok([0; 5])
    );
    // Equal low bits never substitute for the complete generation.
    ram.descriptions[replacement.slot as usize]
        .as_mut()
        .unwrap()
        .generation = replacement.generation + (1 << 32);
    assert_eq!(
        ram.telemetry_description(
            &controller,
            witness,
            u32::from(replacement.slot),
            replacement.generation
        ),
        Ok([0; 5])
    );
    assert_eq!(
        ram.telemetry_description(
            &controller,
            witness,
            u32::from(replacement.slot),
            replacement.generation + (1 << 32)
        ),
        Ok([
            1,
            1,
            1,
            u64::from(replacement.slot),
            replacement.generation + (1 << 32)
        ])
    );
}

#[test]
fn physical_observer_checks_live_exact_source_inode_and_original_payer() {
    let mut ram = Ram::default();
    let mut holder = Fds::default();
    let fd = ram.open(&mut holder, "/etc/motd", READ_ONLY).unwrap();
    let target = source(&ram, &holder, fd).description;
    let mut controller = Fds::default();
    let fd = ram.open(&mut controller, "/etc/motd", READ_ONLY).unwrap();
    let witness = source(&ram, &controller, fd);
    let query = |ram: &Ram<'_>, fds: &Fds, witness| {
        ram.telemetry_description(fds, witness, u32::from(target.slot), target.generation)
    };
    let wrong_source = TentativeOpen {
        description: Token {
            generation: witness.description.generation + (1 << 32),
            ..witness.description
        },
        ..witness
    };
    assert_eq!(
        query(&ram, &controller, wrong_source),
        Err(proto_fs::PERMISSION)
    );
    let other = ram.open(&mut controller, "/", READ_ONLY).unwrap();
    assert_eq!(
        query(&ram, &controller, source(&ram, &controller, other)),
        Err(proto_fs::PERMISSION)
    );
    let root = storage::Root {
        id: 1234,
        generation: 1,
    };
    // A current session root does not rewrite the original description payer.
    controller.root = root;
    assert!(query(&ram, &controller, witness).is_ok());
    let foreign = ram.open(&mut controller, "/etc/motd", READ_ONLY).unwrap();
    assert_eq!(
        query(&ram, &controller, source(&ram, &controller, foreign)),
        Err(proto_fs::PERMISSION)
    );
    controller.departed = true;
    assert_eq!(query(&ram, &controller, witness), Err(proto_fs::PERMISSION));
    controller.departed = false;
    ram.detach_descriptor(&mut controller, witness).unwrap();
    assert_eq!(query(&ram, &controller, witness), Err(proto_fs::PERMISSION));
}
