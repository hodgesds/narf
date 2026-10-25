// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! B initial fixed channel change bracket. This retains the scheduler snapshot
//! across MAC/BB/RF programming; it grants neither calibration nor packet TX.
use super::{
    power,
    rfk::{Error, Interface},
};
#[derive(Clone, Copy)]
struct Step(u8, u32, u32, u32);
#[path = "channel_transition/tables.rs"]
mod tables;
pub(super) const RECIPE: [u8; 32] = tables::RECIPE;
use tables::{ENTER, LEAVE};
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Entering,
    Entered,
    Leaving,
    Finished,
}
#[derive(Default)]
pub(super) struct Transition {
    state: State,
    saved: Option<u32>,
}
impl Transition {
    pub fn state(&self) -> State {
        self.state
    }
    async fn run(&mut self, io: &mut impl Interface, program: &[Step]) -> Result<(), Error> {
        for &Step(kind, address, mask, value) in program {
            io.admit()?;
            match kind {
                0 => {
                    let v = if mask == u32::MAX {
                        value
                    } else {
                        let old = io.read32(address)?;
                        if old == u32::MAX {
                            return Err(power::Error::Gone.into());
                        }
                        (old & !mask) | ((value << mask.trailing_zeros()) & mask)
                    };
                    io.admit()?;
                    io.write32(address, v)?;
                    io.admit()?;
                    let actual = io.read32(address)?;
                    if actual == u32::MAX {
                        return Err(power::Error::Gone.into());
                    }
                    if actual & mask != v & mask {
                        return Err(power::Error::Access.into());
                    }
                }
                1 => {
                    io.delay_us(u64::from(value)).await;
                    io.admit()?;
                }
                2 => {
                    if self.saved.is_some() {
                        return Err(Error::Terminal);
                    }
                    self.saved = Some(io.pause().await?);
                    io.admit()?;
                }
                3 => {
                    io.resume(self.saved.ok_or(Error::Terminal)?).await?;
                    io.admit()?;
                }
                _ => return Err(Error::Table),
            }
        }
        Ok(())
    }
    /// # Safety
    /// Exclusive current qualified B/PHY0/ch1/20 initial owner, global CMAC TX
    /// closed, independently fenced retained DMA, actual WLAN-only arbitration.
    /// Caller retains this bracket/backend across the channel operations and
    /// terminalizes/closes independent engines on any error or dropped future.
    pub async unsafe fn enter(&mut self, io: &mut impl Interface) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Entering;
        self.run(io, ENTER).await?;
        self.state = State::Entered;
        Ok(())
    }
    /// # Safety
    /// Same backend and channel owner as enter, with complete successful actual
    /// MAC/BB/RF channel programming while the bracket remained exclusively held.
    /// Releasing reset/ADC never opens CMAC TX or provides full channel RFK.
    pub async unsafe fn finish(&mut self, io: &mut impl Interface) -> Result<(), Error> {
        if self.state != State::Entered {
            return Err(Error::Terminal);
        }
        self.state = State::Leaving;
        self.run(io, LEAVE).await?;
        self.state = State::Finished;
        Ok(())
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "channel_transition/tests.rs"]
mod tests;
