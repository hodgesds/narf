// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Serialized B firmware scheduler register mailbox; actual firmware owns the
//! CTN register after WCPU startup. Direct writes are not a scheduler receipt.
use super::power::{self, Io};
pub(super) trait Interface: Io {
    fn admit(&mut self) -> Result<(), power::Error>;
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    Idle,
    Pending,
}
#[derive(Default)]
pub(super) struct Mailbox {
    state: State,
    h2c: u8,
    c2h: u8,
}
impl Mailbox {
    pub fn state(&self) -> State {
        self.state
    }
    pub async fn scheduler(
        &mut self,
        io: &mut impl Interface,
        enable: u16,
    ) -> Result<(), power::Error> {
        if self.state != State::Idle {
            return Err(power::Error::Terminal);
        }
        self.state = State::Pending;
        let mut a = Access(io);
        // Never let an unrelated/stale reply satisfy this one serialized
        // operation. There is no other register-message producer in Startup.
        if a.r8(0x8164)? != 0 {
            return Err(power::Error::Access);
        }
        a.poll(0x8160, 0, 1000, 5000).await?;
        // fw.c write_h2c_reg + mac.c hw_sch_tx_en_h2c, SCC MAC0/all.
        for (address, value) in [
            (0x8140, 0x205 | (u32::from(enable) << 16)),
            (0x8144, 0xffff),
            (0x8148, 0),
            (0x814c, 0),
        ] {
            a.w32(address, value)?;
        }
        self.h2c = self.h2c.wrapping_add(1);
        a.counter(15, self.h2c)?;
        a.w8(0x8160, 1)?;
        a.poll(0x8164, 1, 1, 1_000_000).await?;
        let mut words = [0; 4];
        for (i, word) in words.iter_mut().enumerate() {
            *word = a.r32(0x8150 + i as u32 * 4)?;
        }
        let length = (words[0] >> 8) & 15;
        if !(1..=4).contains(&length) || words[0] & 0x7f != 4 {
            return Err(power::Error::Access);
        }
        a.w8(0x8164, 0)?;
        self.c2h = self.c2h.wrapping_add(1);
        a.counter(0xf0, self.c2h)?;
        // A correct reply is also insufficient if the command was never
        // consumed or the requested actual scheduler state did not change.
        if a.r8(0x8160)? != 0 || a.r16(0xc348)? != enable {
            return Err(power::Error::Access);
        }
        self.state = State::Idle;
        Ok(())
    }
}
struct Access<'a, I>(&'a mut I);
impl<I: Interface> Access<'_, I> {
    fn r8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.0.admit()?;
        let v = self.0.read8(a)?;
        if matches!(a, 0x8160 | 0x8164) && v == 255 {
            return Err(power::Error::Gone);
        }
        Ok(v)
    }
    fn r16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.0.admit()?;
        self.0.read16(a)
    }
    fn r32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.0.admit()?;
        self.0.read32(a)
    }
    fn w8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.0.admit()?;
        self.0.write8(a, v)
    }
    fn w32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.0.admit()?;
        self.0.write32(a, v)
    }
    fn counter(&mut self, mask: u8, value: u8) -> Result<(), power::Error> {
        let old = self.r8(0x1f5)?;
        self.w8(
            0x1f5,
            (old & !mask) | ((value << mask.trailing_zeros()) & mask),
        )
    }
    async fn poll(&mut self, a: u32, v: u8, step: u64, budget: u64) -> Result<(), power::Error> {
        let start = self.0.now_us();
        loop {
            if self.r8(a)? == v {
                return Ok(());
            }
            if self.0.now_us().saturating_sub(start) >= budget {
                return Err(power::Error::Timeout);
            }
            self.0.admit()?;
            self.0.delay_us(step).await;
            self.0.admit()?;
        }
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "scheduler_mailbox/tests.rs"]
mod tests;
