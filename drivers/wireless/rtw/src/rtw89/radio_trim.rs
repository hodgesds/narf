// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Real factory-qualified B thermal/PA physical trim application.
use super::{
    factory_b::Calibration,
    rfk::{Error, Interface},
};
#[path = "radio_trim/regs.rs"]
mod regs;
use regs::*;
pub(super) const RECIPE: [u8; 32] = regs::RECIPE;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Preparing,
    Applied,
}
#[derive(Default)]
pub(super) struct Trim {
    state: State,
}
impl Trim {
    pub fn state(&self) -> State {
        self.state
    }
    async fn write(io: &mut impl Interface, p: u8, a: u32, m: u32, v: u32) -> Result<(), Error> {
        io.admit()?;
        io.rf_write(p, a, m, v).await?;
        io.admit()?;
        if io.rf_read(p, a, m).await? != v {
            return Err(super::power::Error::Access.into());
        }
        Ok(())
    }
    /// # Safety
    /// Current full measured B radio recipe, same actual completed factory maps,
    /// stopped/awake initial radio and exclusive analog/reset ownership. The
    /// enclosing owner terminalizes on failure/drop and retains uncertain DMA.
    pub async unsafe fn prepare(
        &mut self,
        io: &mut impl Interface,
        c: &Calibration,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Preparing;
        io.admit()?;
        if c.thermal_programmed {
            for p in 0..2 {
                let raw = c.thermal_trim[p];
                let v = ((raw & 1) << 3) | ((raw & 0x1f) >> 1);
                Self::write(io, p as u8, RR_TM2, RR_TM2_OFF, u32::from(v)).await?;
            }
        }
        if c.pa_programmed {
            for p in 0..2 {
                let raw = c.pa_bias[p];
                Self::write(io, p as u8, RR_BIASA, RR_BIASA_TXG, u32::from(raw & 15)).await?;
                Self::write(io, p as u8, RR_BIASA, RR_BIASA_TXA, u32::from(raw >> 4)).await?;
            }
        }
        io.admit()?;
        self.state = State::Applied;
        Ok(())
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_trim/tests.rs"]
mod tests;
