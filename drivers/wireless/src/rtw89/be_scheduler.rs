// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Source RTL8922A32-bit stop_sch_tx_v2/resume_sch_tx_v2 (mac_be.c).
//! Unlike AX this is a direct checked register path even after FW startup.
//! Original saved state is owned here; callers cannot supply replacement bits.
use super::{cold_8922a::Regs, power};
const ADDRESS: u32 = 0x10398;
const ALL: u32 = 0x3ffff;
pub(super) trait Interface: Regs {
    fn active(&mut self) -> Result<(), power::Error>;
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    Idle,
    Paused,
    Failed,
}
#[derive(Default)]
pub(super) struct Scheduler {
    state: State,
    saved: Option<u32>,
}
impl Scheduler {
    pub(super) fn state(&self) -> State {
        self.state
    }
    pub(super) fn pause(&mut self, io: &mut impl Interface) -> Result<u32, power::Error> {
        if self.state != State::Idle {
            return Err(power::Error::Terminal);
        }
        self.state = State::Failed;
        let saved = read(io)?;
        self.saved = Some(saved); // preserve original before possibly accepted stop
        change(io, 0)?;
        self.state = State::Paused;
        Ok(saved)
    }
    pub(super) fn resume(
        &mut self,
        io: &mut impl Interface,
        original: u32,
    ) -> Result<(), power::Error> {
        if self.state != State::Paused || self.saved != Some(original) {
            self.state = State::Failed;
            return Err(power::Error::Terminal);
        }
        self.state = State::Failed;
        change(io, original)?;
        self.saved = None;
        self.state = State::Idle;
        Ok(())
    }
}
fn read(io: &mut impl Interface) -> Result<u32, power::Error> {
    io.active()?;
    let value = io.read32(ADDRESS)?;
    if value == u32::MAX {
        Err(power::Error::Gone)
    } else {
        Ok(value)
    }
}
fn change(io: &mut impl Interface, value: u32) -> Result<(), power::Error> {
    let current = read(io)?;
    io.active()?;
    io.write32(ADDRESS, (current & !ALL) | (value & ALL))?;
    if read(io)? & ALL != value & ALL {
        return Err(power::Error::Access);
    }
    io.active()
}
#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use crate::rtw89::cold_8922a::Binding;
    use alloc::{vec, vec::Vec};
    use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
    struct Model {
        word: u32,
        writes: Vec<(u32, u32)>,
        count: usize,
        fail_at: Option<usize>,
        drop: bool,
    }
    impl Model {
        fn new() -> Self {
            Self {
                word: 0xa5a7f123,
                writes: Vec::new(),
                count: 0,
                fail_at: None,
                drop: false,
            }
        }
        fn access(&mut self) -> Result<(), power::Error> {
            self.count += 1;
            if self.fail_at.is_some_and(|at| self.count >= at) {
                Err(power::Error::Access)
            } else {
                Ok(())
            }
        }
    }
    impl Regs for Model {
        fn binding(&self) -> Binding {
            unreachable!("scheduler only observes actual source register")
        }
        fn current(&mut self) -> Result<(), power::Error> {
            self.access()
        }
        fn read8(&mut self, _: u32) -> Result<u8, power::Error> {
            Err(power::Error::Access)
        }
        fn read16(&mut self, _: u32) -> Result<u16, power::Error> {
            Err(power::Error::Access)
        }
        fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
            self.access()?;
            if a != ADDRESS {
                return Err(power::Error::Access);
            }
            Ok(self.word)
        }
        fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
            Err(power::Error::Access)
        }
        fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
            Err(power::Error::Access)
        }
        fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
            self.access()?;
            if a != ADDRESS {
                return Err(power::Error::Access);
            }
            self.writes.push((a, v));
            if !self.drop {
                self.word = v;
            }
            Ok(())
        }
        fn poll32(&mut self, _: u32, _: u32, _: u32, _: u64) -> Result<(), power::Error> {
            Err(power::Error::Access)
        }
        fn delay_us(&mut self, _: u64) -> Result<(), power::Error> {
            Err(power::Error::Access)
        }
    }
    impl Interface for Model {
        fn active(&mut self) -> Result<(), power::Error> {
            self.access()
        }
    }
    fn smoke_rtw8922a_scheduler_be32_original_saved_state_and_refusal() -> TestResult {
        let mut io = Model::new();
        let mut owner = Scheduler::default();
        kt_assert_eq!(owner.pause(&mut io), Ok(0xa5a7f123));
        kt_assert_eq!(owner.state(), State::Paused);
        // Preserve only current reserved/high bits on resume, not the old
        // snapshot's reserved bits; lower18 bits come from original owner.
        io.word = 0x5a580000;
        kt_assert_eq!(owner.resume(&mut io, 0xa5a7f123), Ok(()));
        kt_assert_eq!(
            io.writes,
            vec![(0x10398, 0xa5a40000), (0x10398, 0x5a5bf123)]
        );
        kt_assert_eq!(owner.state(), State::Idle);
        let mut bad = Model::new();
        let mut owner = Scheduler::default();
        kt_assert!(owner.pause(&mut bad).is_ok());
        let before = bad.writes.len();
        kt_assert_eq!(owner.resume(&mut bad, 0xffff), Err(power::Error::Terminal));
        kt_assert_eq!(bad.writes.len(), before);
        kt_assert_eq!(owner.state(), State::Failed);
        let mut drop = Model::new();
        drop.drop = true;
        kt_assert_eq!(
            Scheduler::default().pause(&mut drop),
            Err(power::Error::Access)
        );
        let mut full = Model::new();
        let mut owner = Scheduler::default();
        kt_assert!(owner.pause(&mut full).is_ok());
        kt_assert!(owner.resume(&mut full, 0xa5a7f123).is_ok());
        for at in 1..=full.count {
            let mut io = Model::new();
            io.fail_at = Some(at);
            let mut owner = Scheduler::default();
            if let Ok(saved) = owner.pause(&mut io) {
                kt_assert!(owner.resume(&mut io, saved).is_err());
            }
            kt_assert_eq!(owner.state(), State::Failed);
            let before = io.writes.len();
            kt_assert!(owner.resume(&mut io, 0xa5a7f123).is_err());
            kt_assert_eq!(io.writes.len(), before);
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89/8922a",
        smoke_rtw8922a_scheduler_be32_original_saved_state_and_refusal
    );
}
