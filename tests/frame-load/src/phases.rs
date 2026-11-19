// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The phases of the probe, by the clock of the guest. Each phase is 4 s (240
//! periods of 60 Hz), the reference of the CPU load 1 s, and has a scene on the
//! screen and a set of loads running.
//! Every load program derives its own start and stop from this table and the
//! epoch, so the conductor does not have to tell them: they are started by
//! init at boot, sleep until their first phase, work while the phase lasts
//! and sleep again.

/// The period of the compositor's clock at 60 Hz, in ns (the default of the
/// service's `period_ns`).
pub const PERIOD_NS: u64 = 16_666_667;
/// The length of a phase, in periods and in ns.
pub const PERIODS: u64 = 240;
pub const PHASE_NS: u64 = PERIODS * PERIOD_NS;
/// The reference phase of the CPU load: one second, 60 periods.
pub const HOG_REF_PERIODS: u64 = 60;
/// Where the first phase starts on the guest's clock (time since boot), in
/// ns. The programs start at boot and the image is up in a few seconds of
/// guest time, so 30 s leave the room, and a program that starts later than
/// that says so and fails.
pub const EPOCH_NS: u64 = 30_000_000_000;

/// What is on the screen in a phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scene {
    /// Nothing is drawn: the service has no window and must not wake.
    None,
    /// A small window of 160 by 100 points, composed from a copy (four bands).
    P,
    /// A window of the whole screen, composed from a copy.
    F,
    /// A window of the first revision over the whole screen: shown directly.
    D,
    /// Eight windows of 320 by 200 points with an alpha, over one another in one
    /// place, each posted whole every period: more bands than the cap lets the
    /// service make in a period.
    O,
}

/// Which loads run in a phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Loads {
    pub cpu: bool,
    pub files: bool,
    pub net: bool,
}

/// The phases, in the order they run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Quiet,
    Idle,
    Full,
    Cpu,
    Files,
    Net,
    FullLoaded,
    Direct,
    HogRef,
    Overload,
}

/// The order of the phases: the loads are added one after another, and the
/// last two have them all.
pub const ORDER: [Phase; 10] = [
    Phase::Quiet,
    Phase::Idle,
    Phase::Full,
    Phase::Cpu,
    Phase::Files,
    Phase::Net,
    Phase::FullLoaded,
    Phase::Direct,
    Phase::HogRef,
    Phase::Overload,
];

impl Phase {
    pub const fn name(self) -> &'static str {
        match self {
            Phase::Quiet => "quiet",
            Phase::Idle => "idle",
            Phase::Full => "full",
            Phase::Cpu => "cpu",
            Phase::Files => "files",
            Phase::Net => "net",
            Phase::FullLoaded => "full-loaded",
            Phase::Direct => "direct",
            Phase::HogRef => "hog-ref",
            Phase::Overload => "overload",
        }
    }

    pub const fn scene(self) -> Scene {
        match self {
            Phase::Quiet | Phase::HogRef => Scene::None,
            Phase::Overload => Scene::O,
            Phase::Idle | Phase::Cpu | Phase::Files | Phase::Net => Scene::P,
            Phase::Full | Phase::FullLoaded => Scene::F,
            Phase::Direct => Scene::D,
        }
    }

    pub const fn loads(self) -> Loads {
        let (cpu, files, net) = match self {
            Phase::Quiet | Phase::Idle | Phase::Full => (false, false, false),
            Phase::Cpu | Phase::HogRef | Phase::Overload => (true, false, false),
            Phase::Files => (true, true, false),
            Phase::Net | Phase::FullLoaded | Phase::Direct => (true, true, true),
        };
        Loads { cpu, files, net }
    }

    /// The periods of the phase.
    pub const fn periods(self) -> u64 {
        match self {
            Phase::HogRef => HOG_REF_PERIODS,
            _ => PERIODS,
        }
    }

    /// The length of the phase in ns.
    pub const fn duration_ns(self) -> u64 {
        self.periods() * PERIOD_NS
    }

    const fn index(self) -> usize {
        let mut i = 0;
        while i < ORDER.len() {
            if ORDER[i] as u8 == self as u8 {
                return i;
            }
            i += 1;
        }
        0
    }
}

/// The phases on the clock: the epoch they count from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub epoch_ns: u64,
}

impl Schedule {
    pub const DEFAULT: Schedule = Schedule { epoch_ns: EPOCH_NS };

    pub const fn start_of(&self, phase: Phase) -> u64 {
        let mut at = self.epoch_ns;
        let mut i = 0;
        while i < phase.index() {
            at += ORDER[i].duration_ns();
            i += 1;
        }
        at
    }

    pub const fn end_of(&self, phase: Phase) -> u64 {
        self.start_of(phase) + phase.duration_ns()
    }

    /// The end of the last phase.
    pub const fn finish(&self) -> u64 {
        self.end_of(ORDER[ORDER.len() - 1])
    }

    /// The phase `now_ns` is in, or `None` before the epoch and after the end.
    pub fn at(&self, now_ns: u64) -> Option<Phase> {
        now_ns.checked_sub(self.epoch_ns)?;
        ORDER
            .iter()
            .copied()
            .find(|&p| now_ns >= self.start_of(p) && now_ns < self.end_of(p))
    }

    /// The first phase after `now_ns` in which `wants` is true, or the one
    /// `now_ns` is in when that one wants it: where a load that sleeps wakes.
    pub fn next_wanted(&self, now_ns: u64, wants: impl Fn(Phase) -> bool) -> Option<Phase> {
        ORDER
            .iter()
            .copied()
            .find(|&p| self.end_of(p) > now_ns && wants(p))
    }
}

/// The scenes of the hour, one minute each in turn: P, F, D (the loads all
/// the time).
pub const HOUR_SCENES: [Scene; 3] = [Scene::P, Scene::F, Scene::D];

pub const fn hour_scene(minute: u64) -> Scene {
    HOUR_SCENES[(minute % 3) as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_phase_is_240_periods_of_60_hz() {
        assert_eq!(PERIODS, 240);
        // 240 * 16 666 667 ns.
        assert_eq!(PHASE_NS, 4_000_000_080);
    }

    /// The order the plan fixes: the loads join one after another (the CPU,
    /// the files, the network), the stress and the direct phases have them all.
    #[test]
    fn the_phases_come_in_the_planned_order() {
        let names: Vec<&str> = ORDER.iter().map(|p| p.name()).collect();
        assert_eq!(
            names,
            [
                "quiet",
                "idle",
                "full",
                "cpu",
                "files",
                "net",
                "full-loaded",
                "direct",
                "hog-ref",
                "overload"
            ]
        );
        let at = |p: Phase| ORDER.iter().position(|&o| o == p).unwrap();
        assert!(at(Phase::Net) < at(Phase::FullLoaded));
        assert!(at(Phase::HogRef) + 1 == at(Phase::Overload));
        assert!(at(Phase::Files) < at(Phase::Net));
        assert!(at(Phase::Cpu) < at(Phase::Files));
    }

    #[test]
    fn each_phase_has_its_scene_and_loads() {
        assert_eq!(Phase::Quiet.scene(), Scene::None);
        assert_eq!(Phase::Idle.scene(), Scene::P);
        assert_eq!(Phase::Full.scene(), Scene::F);
        assert_eq!(Phase::FullLoaded.scene(), Scene::F);
        assert_eq!(Phase::Overload.scene(), Scene::O);
        assert_eq!(Phase::HogRef.scene(), Scene::None);
        assert_eq!(Phase::Direct.scene(), Scene::D);
        let none = Loads {
            cpu: false,
            files: false,
            net: false,
        };
        assert_eq!(Phase::Quiet.loads(), none);
        assert_eq!(Phase::Full.loads(), none);
        assert_eq!(
            Phase::Files.loads(),
            Loads {
                cpu: true,
                files: true,
                net: false
            }
        );
        let all = Loads {
            cpu: true,
            files: true,
            net: true,
        };
        for p in [Phase::Net, Phase::FullLoaded, Phase::Direct] {
            assert_eq!(p.loads(), all, "{}", p.name());
        }
        // The overload has the CPU load alone, so that the share it keeps
        // means the cap and not the budgets of the files and the network.
        let cpu = Loads {
            cpu: true,
            files: false,
            net: false,
        };
        assert_eq!(Phase::HogRef.loads(), cpu);
        assert_eq!(Phase::Overload.loads(), cpu);
    }

    #[test]
    fn the_schedule_puts_each_phase_after_the_one_before() {
        let s = Schedule::DEFAULT;
        for pair in ORDER.windows(2) {
            assert_eq!(s.end_of(pair[0]), s.start_of(pair[1]));
        }
        assert_eq!(s.start_of(Phase::Quiet), EPOCH_NS);
        assert_eq!(s.finish(), s.end_of(Phase::Overload));
        // The reference of the CPU load is a second.
        assert_eq!(
            s.end_of(Phase::HogRef) - s.start_of(Phase::HogRef),
            1_000_000_020
        );
    }

    #[test]
    fn the_clock_names_the_phase() {
        let s = Schedule { epoch_ns: 1000 };
        assert_eq!(s.at(999), None);
        assert_eq!(s.at(1000), Some(Phase::Quiet));
        assert_eq!(s.at(1000 + PHASE_NS - 1), Some(Phase::Quiet));
        assert_eq!(s.at(1000 + PHASE_NS), Some(Phase::Idle));
        assert_eq!(s.at(s.finish() - 1), Some(Phase::Overload));
        assert_eq!(s.at(s.finish()), None);
    }

    #[test]
    fn a_sleeping_load_wakes_in_its_first_phase() {
        let s = Schedule::DEFAULT;
        let files = |p: Phase| p.loads().files;
        assert_eq!(s.next_wanted(0, files), Some(Phase::Files));
        // In the middle of the files phase the load still wants it.
        let mid = s.start_of(Phase::Files) + PHASE_NS / 2;
        assert_eq!(s.next_wanted(mid, files), Some(Phase::Files));
        // After the last phase nothing is left.
        assert_eq!(s.next_wanted(s.finish(), files), None);
    }

    #[test]
    fn the_hour_turns_p_f_d_each_minute() {
        let scenes: Vec<Scene> = (0..6).map(hour_scene).collect();
        assert_eq!(
            scenes,
            [Scene::P, Scene::F, Scene::D, Scene::P, Scene::F, Scene::D]
        );
    }
}
