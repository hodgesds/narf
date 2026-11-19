// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Source cmac_pwr_en_be window for the two unconditional DM UL fields.
//! The owning radio retains the actual transition stage after any failure.
use super::power;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Power {
    #[default]
    Off,
    Afe,
    Unisolated,
    Powered,
}
impl Power {
    pub(super) fn tuple(self) -> (u32, u32) {
        match self {
            Self::Off => (0, 1 << 25),
            Self::Afe => (0x1f, 1 << 25),
            Self::Unisolated => (0x1f, 0),
            Self::Powered => (0x1f, 1 << 17),
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Busy,
    CompleteOff,
    FailedClosed,
    FailedUnknown,
}
pub(super) trait Interface {
    fn transition(
        &mut self,
        before: Power,
        after: Power,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), power::Error>;
    fn powered_field(&mut self, address: u32, mask: u32, value: u32) -> Result<(), power::Error>;
    /// CURRENT ORIGINAL PCI only; restrictive common closure, no RF source
    /// bypass, reset, reclaim, packet enable or guessed off-domain receipt.
    fn restrict(&mut self) -> Result<(), power::Error>;
}
#[derive(Default)]
pub(super) struct Window {
    state: State,
    power: Power,
}
impl Window {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn fixture_packet_refusal_metadata() -> Self {
        Self {
            state: State::CompleteOff,
            power: Power::Off,
        }
    }
    pub(super) fn state(&self) -> State {
        self.state
    }
    fn step(
        &mut self,
        io: &mut impl Interface,
        next: Power,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), power::Error> {
        io.transition(self.power, next, address, mask, value)?;
        self.power = next;
        Ok(())
    }
    /// # Safety
    /// Same original closed SCC radio, fresh N22W permission for every
    /// transition/effect, MAC0 packets/BB1/ordinary DMA closed. No competing
    /// reset/IRQ/producer. This whole window is synchronous: no executor
    /// cancellation can discard it between polls. Atomic cancellation/source
    /// failure invokes current-original-PCI-only restriction before returning.
    pub(super) unsafe fn program(&mut self, io: &mut impl Interface) -> Result<(), power::Error> {
        if self.state != State::New {
            return Err(power::Error::Terminal);
        }
        self.state = State::Busy;
        let result = (|| {
            self.step(io, Power::Afe, 0x24, 0x1f, 0x1f)?;
            self.step(io, Power::Unisolated, 0x84, 1 << 25, 0)?;
            self.step(io, Power::Powered, 0x84, 1 << 17, 1 << 17)?;
            // C1 is read ONLY after its complete common tuple proves power.
            io.powered_field(0x14000, 3 << 28, 0)?;
            io.powered_field(0x15a84, u32::MAX, 0x0201fe00)?;
            io.powered_field(0x15a78, u32::MAX, 0x00ffec7e)?;
            self.step(io, Power::Unisolated, 0x84, 1 << 17, 0)?;
            self.step(io, Power::Afe, 0x84, 1 << 25, 1 << 25)?;
            self.step(io, Power::Off, 0x24, 0x1f, 0)?;
            Ok(())
        })();
        if result.is_err() {
            self.state = if io.restrict().is_ok() {
                self.power = Power::Off;
                State::FailedClosed
            } else {
                State::FailedUnknown
            };
        } else {
            self.state = State::CompleteOff;
        }
        result
    }
}
