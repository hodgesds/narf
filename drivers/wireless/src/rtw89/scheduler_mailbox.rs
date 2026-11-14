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
pub(super) struct Mailbox {
    state: State,
    h2c: u8,
    c2h: u8,
    /// `chip->h2c_regs[0]`: R_AX_H2CREG_DATA0 (0x8140) on RTL8852B, the
    /// R_AX_H2CREG_DATA0_V1 block (0x7140) on RTL8852C. DATA1..3, C2HREG
    /// DATA0..3 (+0x10) and H2CREG/C2HREG_CTRL (+0x20/+0x24) keep the same
    /// layout in both blocks (reg.h); the R_AX_UDM1 counters are shared.
    base: u32,
    /// RTL8851B (rtw8851b.c `rtw8851b_h2c_regs` is the B block): the
    /// receipt is decoded with the one-path RTL8851B rule.
    n51: bool,
    /// RTL8852A (rtw8852a.c `rtw8852a_h2c_regs` is the B block): the
    /// receipt is decoded with the A rule (same AX part0 as B, marked A).
    a: bool,
}
impl Default for Mailbox {
    fn default() -> Self {
        Self::with_base(0x8140)
    }
}
impl Mailbox {
    const fn with_base(base: u32) -> Self {
        Self {
            state: State::Idle,
            h2c: 0,
            c2h: 0,
            base,
            n51: false,
            a: false,
        }
    }
    /// rtw8852c.c `rtw8852c_h2c_regs`/`rtw8852c_c2h_regs` with
    /// `R_AX_{H2C,C2H}REG_CTRL_V1`; every other chip keeps the B block.
    pub(super) fn for_chip(chip: super::mac::ChipId) -> Self {
        if chip == super::mac::ChipId::Rtl8852C {
            Self::with_base(0x7140)
        } else if chip == super::mac::ChipId::Rtl8851B {
            Self {
                n51: true,
                ..Self::default()
            }
        } else if chip == super::mac::ChipId::Rtl8852A {
            Self {
                a: true,
                ..Self::default()
            }
        } else {
            Self::default()
        }
    }

    pub fn state(&self) -> State {
        self.state
    }
    /// RTL8852B and RTL8852C are AX: GET_FEATURE part0 has no content bytes. Its reply
    /// contains the complete four-word PHY capability record; AX has no part1
    /// query in mac.c::rtw89_mac_setup_phycap.
    pub(super) async fn phycap(
        &mut self,
        io: &mut impl Interface,
    ) -> Result<super::firmware_phycap::Receipt, power::Error> {
        if self.state != State::Idle {
            return Err(power::Error::Terminal);
        }
        self.state = State::Pending;
        let mut a = Access(io, self.base);
        if a.r8(a.1 + 0x24)? != 0 {
            return Err(power::Error::Access);
        }
        a.poll(a.1 + 0x20, 0, 1000, 5000).await?;
        // Recheck after the possibly awaited previous-command consumption.
        if a.r8(a.1 + 0x24)? != 0 {
            return Err(power::Error::Access);
        }
        for (index, value) in [0x103, 0, 0, 0].into_iter().enumerate() {
            a.w32(a.1 + index as u32 * 4, value)?;
        }
        self.h2c = self.h2c.wrapping_add(1);
        a.counter(15, self.h2c)?;
        if a.r8(a.1 + 0x24)? != 0 {
            return Err(power::Error::Access);
        }
        a.w8(a.1 + 0x20, 1)?;
        a.poll(a.1 + 0x24, 1, 1, 1_000_000).await?;
        let mut words = [0; 4];
        for (index, word) in words.iter_mut().enumerate() {
            *word = a.r32(a.1 + 0x10 + index as u32 * 4)?;
        }
        // There is no H2CREG sequence echo contract in AX. A fresh response,
        // exact function/full length, exclusive producer and actual command
        // consumption bind this one-shot query; source counters are retained.
        let receipt = if self.n51 {
            super::firmware_phycap::Receipt::decode_51(words)?
        } else if self.a {
            super::firmware_phycap::Receipt::decode_a(words)?
        } else {
            super::firmware_phycap::Receipt::decode_for(self.base == 0x7140, words)?
        };
        a.w8(a.1 + 0x24, 0)?;
        self.c2h = self.c2h.wrapping_add(1);
        a.counter(0xf0, self.c2h)?;
        if a.r8(a.1 + 0x24)? != 0 || a.r8(a.1 + 0x20)? != 0 {
            return Err(power::Error::Access);
        }
        self.state = State::Idle;
        Ok(receipt)
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
        let mut a = Access(io, self.base);
        // Never let an unrelated/stale reply satisfy this one serialized
        // operation. There is no other register-message producer in Startup.
        if a.r8(a.1 + 0x24)? != 0 {
            return Err(power::Error::Access);
        }
        a.poll(a.1 + 0x20, 0, 1000, 5000).await?;
        // fw.c write_h2c_reg + mac.c hw_sch_tx_en_h2c, SCC MAC0/all.
        for (address, value) in [
            (a.1, 0x205 | (u32::from(enable) << 16)),
            (a.1 + 4, 0xffff),
            (a.1 + 8, 0),
            (a.1 + 0xc, 0),
        ] {
            a.w32(address, value)?;
        }
        self.h2c = self.h2c.wrapping_add(1);
        a.counter(15, self.h2c)?;
        a.w8(a.1 + 0x20, 1)?;
        a.poll(a.1 + 0x24, 1, 1, 1_000_000).await?;
        let mut words = [0; 4];
        for (i, word) in words.iter_mut().enumerate() {
            *word = a.r32(a.1 + 0x10 + i as u32 * 4)?;
        }
        let length = (words[0] >> 8) & 15;
        if !(1..=4).contains(&length) || words[0] & 0x7f != 4 {
            return Err(power::Error::Access);
        }
        a.w8(a.1 + 0x24, 0)?;
        self.c2h = self.c2h.wrapping_add(1);
        a.counter(0xf0, self.c2h)?;
        // A correct reply is also insufficient if the command was never
        // consumed or the requested actual scheduler state did not change.
        if a.r8(a.1 + 0x20)? != 0 || a.r16(0xc348)? != enable {
            return Err(power::Error::Access);
        }
        self.state = State::Idle;
        Ok(())
    }
}
struct Access<'a, I>(&'a mut I, u32);
impl<I: Interface> Access<'_, I> {
    fn r8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.0.admit()?;
        let v = self.0.read8(a)?;
        if (a == self.1 + 0x20 || a == self.1 + 0x24) && v == 255 {
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
