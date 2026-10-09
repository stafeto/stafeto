extern crate std;

use super::*;
use posix_fd::{ControlResult, Flags, Table};
use proto_fs::{Base, ChangeOp, MAX_PATH};
use std::vec::Vec;

fn key(slot: u32, generation: u64) -> OpenKey {
    OpenKey { slot, generation }
}

fn start<'a>(op: ChangeOp, path: &'a [u8], key: OpenKey) -> ChangeStart<'a> {
    ChangeStart {
        key,
        op,
        flags: 0,
        base: Base::Absolute,
        args: if op == ChangeOp::Mkdir {
            [0o755, 0o022, 0, 0]
        } else {
            [0; 4]
        },
        path,
    }
}

/// The service as the loop sees it, with the faults a test asks for. The job
/// lives under its key; the effect happens in the step that finishes it.
#[derive(Default)]
struct Model {
    // The service.
    job: Option<(OpenKey, ChangeOp, Vec<u8>)>,
    second: Option<Vec<u8>>,
    steps_left: u32,
    done: bool,
    effects: u32,
    starts_seen: Vec<OpenKey>,
    seconds_seen: u32,
    steps_seen: u32,
    result: u32,
    restarts: u32,
    retired: bool,
    // Faults.
    full: u32,
    lose_start: bool,
    lose_second: bool,
    lose_step_done: bool,
    authenticate_next_step: bool,
    // The client.
    pauses: u32,
    refreshed: u32,
    live_until: Option<u32>,
    calls: u32,
    releases: Vec<Result<(), Status>>,
    released: u32,
}

impl Model {
    fn new(steps: u32) -> Self {
        Model {
            steps_left: steps,
            ..Model::default()
        }
    }
}

const LOST: Status = Status::Kernel(abi::Error::Interrupted);

impl Wire for Model {
    fn live(&mut self) -> bool {
        match &mut self.live_until {
            None => true,
            Some(0) => false,
            Some(left) => {
                *left -= 1;
                true
            }
        }
    }

    fn start(&mut self, start: &ChangeStart<'_>) -> Result<ChangePhase, Status> {
        self.calls += 1;
        self.starts_seen.push(start.key);
        if self.full > 0 {
            self.full -= 1;
            return Err(Status::Unknown(proto_fs::JOBS_FULL));
        }
        if self.retired {
            return Err(Status::Unknown(proto_fs::OPEN_RETIRED));
        }
        match &self.job {
            Some((known, op, path)) => {
                if *known != start.key || *op != start.op || path != start.path {
                    return Err(Status::Unknown(proto_fs::PERMISSION));
                }
            }
            None => self.job = Some((start.key, start.op, start.path.to_vec())),
        }
        if core::mem::take(&mut self.lose_start) {
            return Err(LOST);
        }
        Ok(ChangePhase::Captured)
    }

    fn second(&mut self, key: OpenKey, _base: Base, bytes: &[u8]) -> Result<(), Status> {
        self.calls += 1;
        self.seconds_seen += 1;
        let Some((known, op, _)) = &self.job else {
            return Err(Status::Unknown(proto_fs::NO_ENTRY));
        };
        if *known != key || !op.needs_second() {
            return Err(Status::Unknown(proto_fs::INVALID_ARGUMENT));
        }
        match &self.second {
            Some(first) if first != bytes => {
                return Err(Status::Unknown(proto_fs::PERMISSION));
            }
            _ => self.second = Some(bytes.to_vec()),
        }
        if core::mem::take(&mut self.lose_second) {
            return Err(LOST);
        }
        Ok(())
    }

    fn step(
        &mut self,
        _key: OpenKey,
        out: &mut [u8; RESULT_MAX],
    ) -> Result<Option<ChangeDone>, Status> {
        self.calls += 1;
        self.steps_seen += 1;
        if core::mem::take(&mut self.authenticate_next_step) {
            return Err(Status::Unknown(proto_fs::AUTHENTICATING));
        }
        let Some((_, op, _)) = &self.job else {
            return Err(Status::Unknown(proto_fs::NO_ENTRY));
        };
        if op.needs_second() && self.second.is_none() {
            return Err(Status::Unknown(proto_fs::INVALID_ARGUMENT));
        }
        if !self.done {
            self.steps_left = self.steps_left.saturating_sub(1);
            if self.steps_left > 0 {
                return Ok(None);
            }
            self.done = true;
            self.effects += 1;
            if core::mem::take(&mut self.lose_step_done) {
                return Err(LOST);
            }
        }
        out[..3].copy_from_slice(b"abc");
        Ok(Some(ChangeDone {
            result: self.result,
            restarts: self.restarts,
            value: 7,
            length: 3,
        }))
    }

    fn release(&mut self, _key: OpenKey) -> Result<(), Status> {
        self.released += 1;
        if self.releases.is_empty() {
            Ok(())
        } else {
            self.releases.remove(0)
        }
    }

    fn authenticate(&mut self) -> Result<(), Status> {
        self.refreshed += 1;
        Ok(())
    }

    fn wait_for_room(&mut self) {
        self.pauses += 1;
    }
}

fn go(model: &mut Model, op: ChangeOp, second: Option<&[u8]>) -> Result<ChangeDone, Failure> {
    let mut out = [0; RESULT_MAX];
    drive(
        model,
        &start(op, b"/tmp/a", key(3, 9)),
        second.map(|bytes| (Base::Absolute, bytes)),
        &mut out,
    )
}

#[test]
fn a_job_runs_from_start_to_done_and_the_result_comes_back() {
    let mut model = Model::new(3);
    model.result = 0;
    model.restarts = 2;
    let mut out = [0; RESULT_MAX];
    let done = drive(
        &mut model,
        &start(ChangeOp::Mkdir, b"/tmp/a", key(3, 9)),
        None,
        &mut out,
    )
    .unwrap();
    assert_eq!((done.result, done.restarts, done.value), (0, 2, 7));
    assert_eq!(&out[..done.length], b"abc");
    assert_eq!((model.steps_seen, model.effects), (3, 1));
    assert_eq!(model.seconds_seen, 0);
}

#[test]
fn the_error_of_the_operation_is_a_result_and_not_a_failure() {
    let mut model = Model::new(1);
    model.result = proto_fs::NO_ENTRY;
    let done = go(&mut model, ChangeOp::Unlink, None).unwrap();
    assert_eq!(done.result, proto_fs::NO_ENTRY);
}

#[test]
fn a_lost_start_reply_sends_the_same_start_and_the_effect_happens_once() {
    let mut model = Model::new(2);
    model.lose_start = true;
    go(&mut model, ChangeOp::Mkdir, None).unwrap();
    // The same key twice: no new key was taken for the repeat.
    assert_eq!(model.starts_seen, [key(3, 9), key(3, 9)]);
    assert_eq!(model.effects, 1);
}

#[test]
fn a_full_table_makes_the_loop_sleep_and_ask_again_with_the_same_key() {
    let mut model = Model::new(1);
    model.full = 2;
    go(&mut model, ChangeOp::Mkdir, None).unwrap();
    assert_eq!(model.pauses, 2);
    assert_eq!(model.starts_seen, [key(3, 9), key(3, 9), key(3, 9)]);
    assert_eq!(model.effects, 1);
}

#[test]
fn a_full_table_never_reaches_the_caller_however_long_it_lasts() {
    let mut model = Model::new(1);
    model.full = 5_000;
    assert!(go(&mut model, ChangeOp::Mkdir, None).is_ok());
    assert_eq!(model.pauses, 5_000);
}

#[test]
fn a_retired_key_is_an_io_error_and_no_new_key_is_taken() {
    let mut model = Model::new(1);
    model.retired = true;
    assert_eq!(go(&mut model, ChangeOp::Mkdir, None), Err(Failure::Io));
    assert_eq!(model.starts_seen, [key(3, 9)]);
    assert_eq!(model.effects, 0);
}

#[test]
fn a_lost_second_reply_sends_the_same_bytes_and_the_effect_happens_once() {
    let mut model = Model::new(2);
    model.lose_second = true;
    go(&mut model, ChangeOp::Rename, Some(b"/tmp/b")).unwrap();
    assert_eq!(model.seconds_seen, 2);
    assert_eq!(model.second.as_deref(), Some(&b"/tmp/b"[..]));
    assert_eq!(model.effects, 1);
}

#[test]
fn second_comes_before_the_first_step_of_a_two_path_operation() {
    let mut model = Model::new(1);
    go(&mut model, ChangeOp::Link, Some(b"/tmp/b")).unwrap();
    // A step before Second would have been refused with INVALID_ARGUMENT.
    assert_eq!(model.seconds_seen, 1);
    assert_eq!(model.effects, 1);
}

#[test]
fn a_symlink_may_send_an_empty_content() {
    let mut model = Model::new(1);
    go(&mut model, ChangeOp::Symlink, Some(b"")).unwrap();
    assert_eq!(model.second.as_deref(), Some(&b""[..]));
}

#[test]
fn a_lost_reply_of_the_step_that_finished_gives_the_saved_outcome() {
    let mut model = Model::new(2);
    model.lose_step_done = true;
    let done = go(&mut model, ChangeOp::Unlink, None).unwrap();
    assert_eq!(done.value, 7);
    assert_eq!(model.effects, 1);
}

#[test]
fn a_refresh_of_the_credentials_is_completed_and_the_request_repeats() {
    let mut model = Model::new(1);
    model.authenticate_next_step = true;
    go(&mut model, ChangeOp::Access, None).unwrap();
    assert_eq!(model.refreshed, 1);
    assert_eq!(model.effects, 1);
}

#[test]
fn a_dropped_record_stops_the_loop_before_the_next_request() {
    // The record is live for the Start and the first Step, then a fork child
    // finds it dropped.
    let mut model = Model::new(10);
    model.live_until = Some(2);
    assert_eq!(go(&mut model, ChangeOp::Mkdir, None), Err(Failure::Io));
    assert_eq!(model.calls, 2);
    assert_eq!(model.effects, 0);
}

#[test]
fn a_dropped_record_stops_the_loop_before_the_start_too() {
    let mut model = Model::new(1);
    model.live_until = Some(0);
    assert_eq!(go(&mut model, ChangeOp::Mkdir, None), Err(Failure::Io));
    assert_eq!(model.calls, 0);
}

#[test]
fn an_unexpected_status_is_given_back() {
    let mut model = Model::new(1);
    model.job = Some((key(3, 9), ChangeOp::Unlink, b"/other".to_vec()));
    assert_eq!(
        go(&mut model, ChangeOp::Unlink, None),
        Err(Failure::Status(Status::Unknown(proto_fs::PERMISSION)))
    );
}

#[test]
fn release_repeats_until_the_service_answers() {
    let mut model = Model::new(1);
    model.releases = [LOST, LOST, LOST].map(Err).to_vec();
    release(&mut model, key(3, 9));
    assert_eq!(model.released, 4);
}

#[test]
fn release_asks_for_a_refresh_and_then_repeats() {
    let mut model = Model::new(1);
    model.releases = std::vec![Err(Status::Unknown(proto_fs::AUTHENTICATING))];
    release(&mut model, key(3, 9));
    assert_eq!((model.refreshed, model.released), (1, 2));
}

#[test]
fn release_ends_when_the_session_is_gone() {
    let mut model = Model::new(1);
    model.releases = std::vec![Err(Status::Kernel(abi::Error::BadHandle))];
    release(&mut model, key(3, 9));
    assert_eq!(model.released, 1);
}

// The choice of the records to release.

type Records = Table<u32, 32, (), (), Frame>;

fn owner(id: u64) -> OwnerToken {
    OwnerToken::new(id).unwrap()
}

fn all(table: &Records) -> Vec<(ControlToken, ControlSnapshot<Frame>)> {
    table
        .control_tokens()
        .map(|token| (token, table.control_snapshot(token).unwrap()))
        .collect()
}

fn pick(
    table: &Records,
    me: Option<OwnerToken>,
    current: Frame,
    skip: Option<ControlToken>,
) -> Option<(ControlToken, bool)> {
    pick_abandoned(me, current, skip, all(table).into_iter())
}

#[test]
fn a_record_whose_frame_contains_the_current_one_is_alive() {
    let mut table = Records::default();
    let outer = Frame::main(0x9000);
    table.begin_control(owner(1), outer).unwrap();
    // A handler called the operation from below.
    assert_eq!(
        pick(&table, Some(owner(1)), Frame::main(0x8000), None),
        None
    );
    // And from the alternate stack, which lies inside every main frame.
    assert_eq!(
        pick(&table, Some(owner(1)), Frame { z: 1, sp: 0xf000 }, None),
        None
    );
}

#[test]
fn a_record_whose_frame_is_gone_is_abandoned() {
    let mut table = Records::default();
    let (token, _) = table.begin_control(owner(1), Frame::main(0x8000)).unwrap();
    // The thread is back above it, or at the same place, in a new operation.
    for sp in [0x8000, 0x8001, 0x9000] {
        assert_eq!(
            pick(&table, Some(owner(1)), Frame::main(sp), None),
            Some((token, true)),
            "sp {sp:#x}"
        );
    }
    // The record of an operation on the main stack, collected from a handler
    // on the alternate stack that was entered after the operation was left.
    // The handler lies inside the operation's frame, so it stays.
    assert_eq!(
        pick(&table, Some(owner(1)), Frame { z: 1, sp: 0x10 }, None),
        None
    );
}

#[test]
fn the_operation_itself_is_never_picked() {
    let mut table = Records::default();
    let (token, _) = table.begin_control(owner(1), Frame::main(0x8000)).unwrap();
    assert_eq!(
        pick(&table, Some(owner(1)), Frame::main(0x8000), Some(token)),
        None
    );
}

#[test]
fn the_records_of_other_threads_are_left_alone() {
    let mut table = Records::default();
    table.begin_control(owner(2), Frame::main(0x8000)).unwrap();
    assert_eq!(
        pick(&table, Some(owner(1)), Frame::main(0x9000), None),
        None
    );
}

#[test]
fn a_record_without_an_owner_is_released_by_whoever_finds_it() {
    let mut table = Records::default();
    let (token, _) = table.begin_control(owner(2), Frame::main(0x8000)).unwrap();
    table.abandon_control_owner(owner(2)).unwrap();
    assert_eq!(
        pick(&table, Some(owner(1)), Frame::main(0x7000), None),
        Some((token, false))
    );
    // A helper without a thread of its own takes it as well.
    assert_eq!(
        pick(&table, None, Frame::main(0), None),
        Some((token, false))
    );
}

#[test]
fn a_helper_without_a_thread_leaves_the_records_with_owners() {
    let mut table = Records::default();
    table.begin_control(owner(1), Frame::main(0x8000)).unwrap();
    assert_eq!(pick(&table, None, Frame::main(0x9000), None), None);
}

#[test]
fn a_completed_record_of_a_left_operation_is_picked_too() {
    let mut table = Records::default();
    let (token, claim) = table.begin_control(owner(1), Frame::main(0x8000)).unwrap();
    table
        .complete_control(claim, ControlResult::Value(0))
        .unwrap();
    assert_eq!(
        pick(&table, Some(owner(1)), Frame::main(0x9000), None),
        Some((token, true))
    );
}

#[test]
fn the_first_found_record_is_picked_and_the_rest_follow() {
    let mut table = Records::default();
    let fd = table.insert(1, Flags::default());
    assert!(fd.is_ok());
    let (a, _) = table.begin_control(owner(1), Frame::main(0x8000)).unwrap();
    let (b, _) = table.begin_control(owner(1), Frame::main(0x7000)).unwrap();
    let first = pick(&table, Some(owner(1)), Frame::main(0x9000), None).unwrap();
    assert_eq!(first, (a, true));
    table.control_begin_cleanup(a).unwrap();
    table.control_finish_cleanup(a).unwrap();
    table.ack_control(a, owner(1)).unwrap();
    assert_eq!(
        pick(&table, Some(owner(1)), Frame::main(0x9000), None),
        Some((b, true))
    );
}

// The refusals of the virtual names.

#[test]
fn the_virtual_names_are_refused_by_the_table_of_the_layer() {
    use Named::*;
    use Refusal::*;
    let cases = [
        (Unlink, true, false, Some(Busy)),
        (Rmdir, true, false, Some(Busy)),
        (Mkdir, true, false, Some(Exists)),
        (Symlink, true, false, Some(Exists)),
        (Link, true, false, Some(CrossDevice)),
        (Link, false, true, Some(Exists)),
        (Link, true, true, Some(CrossDevice)),
        (Rename, true, false, Some(CrossDevice)),
        (Rename, false, true, Some(CrossDevice)),
        (Rename, true, true, Some(CrossDevice)),
        (Access, true, false, Some(ByMetadata)),
        (Chmod, true, false, Some(ReadOnly)),
        (Chown, true, false, Some(ReadOnly)),
        (Times, true, false, Some(ReadOnly)),
    ];
    for (op, first, second, expected) in cases {
        assert_eq!(virtual_refusal(op, first, second), expected, "{op:?}");
        // A name that is no virtual name passes.
        assert_eq!(virtual_refusal(op, false, false), None, "{op:?}");
    }
    // The new name of a symlink is the first and only path; the second is
    // never set for the single-path operations.
    assert_eq!(virtual_refusal(Mkdir, false, true), None);
}

// The access check by metadata.

#[test]
fn access_follows_the_bits_of_the_class_of_the_caller() {
    // 0o640 owned by 10:20.
    let check = |uid, gid, access| mode_allows(0o640, false, 10, 20, uid, gid, access);
    assert!(check(10, 99, 4 | 2));
    assert!(!check(10, 99, 1));
    assert!(check(11, 20, 4));
    assert!(!check(11, 20, 2));
    assert!(!check(11, 21, 4));
    // The owner class applies to the owner even if the group would give more.
    assert!(!mode_allows(0o070, false, 10, 20, 10, 20, 4));
    assert!(mode_allows(0o070, false, 10, 20, 11, 20, 7));
    // F_OK passes for any class.
    assert!(mode_allows(0, false, 10, 20, 11, 21, 0));
}

#[test]
fn the_superuser_executes_only_what_can_run_or_be_entered() {
    assert!(mode_allows(0, false, 10, 20, 0, 0, 4 | 2));
    assert!(!mode_allows(0o666, false, 10, 20, 0, 0, 1));
    assert!(mode_allows(0o100, false, 10, 20, 0, 0, 1));
    assert!(mode_allows(0o000, true, 10, 20, 0, 0, 1));
}

#[test]
fn two_path_operations_are_rename_and_link() {
    assert!(two_paths(ChangeOp::Rename));
    assert!(two_paths(ChangeOp::Link));
    assert!(!two_paths(ChangeOp::Symlink));
    assert!(!two_paths(ChangeOp::Unlink));
    assert_eq!(MAX_PATH, 511);
}
