// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Real RTL8852A/B RF transactions, separate from PCIe PHY MDIO.
//! RTL8852B/C/8851B: Linux phy.c::{read,write}_rf_v1 (SWSI unless the
//! 0x10000 direct-select bit is set); RTL8852A: phy.c `rtw89_phy_read_rf`/
//! `rtw89_phy_write_rf` (phy.c:928/1128, rtw8852a.c `rtw8852a_chip_ops`),
//! which always use the direct aperture at `addr & 0xff`. phy_gen_ax
//! cr_base=0x10000.
//! The direct RF bases are per chip: RTL8852A uses `rf_base_addr`
//! {0xc000, 0xd000} (rtw8852a.c `rtw8852a_chip_info`), every other AX chip
//! {0xe000, 0xf000} (rtw8852b/c `rtw8852b_chip_info` / `rtw8852c_chip_info`).
use super::{
    mac::ChipId,
    power::{Error, Io},
};
const BASE: u32 = 0x10000;
const RF_MASK: u32 = 0xfffff;
const SWSI: u32 = BASE + 0x174c;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    Idle,
    Busy,
    Terminal,
}
pub(super) struct Rf {
    state: State,
    /// The chip whose `rf_base_addr` selects the direct RF bases; the
    /// SWSI path is chip-independent (same `BASE` + `SWSI` registers).
    chip: ChipId,
}
impl Default for Rf {
    /// The historical B owner: every pre-A caller keeps B's bases.
    fn default() -> Self {
        Self::for_chip(ChipId::Rtl8852B)
    }
}
impl Rf {
    /// An RF owner for `chip` (`Rf::default()` is the B owner).
    pub fn for_chip(chip: ChipId) -> Self {
        Self {
            state: State::Idle,
            chip,
        }
    }
    pub fn state(&self) -> State {
        self.state
    }
    fn begin(&mut self, path: u8, address: u32, mask: u32) -> Result<(), Error> {
        if self.state != State::Idle {
            return Err(Error::Terminal);
        }
        if path > 1 || address & !0x100ff != 0 || mask & RF_MASK == 0 {
            return Err(Error::Unsupported);
        }
        self.state = State::Busy;
        Ok(())
    }
    fn end<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        self.state = if result.is_ok() {
            State::Idle
        } else {
            State::Terminal
        };
        result
    }
    /// RTL8852A has no SWSI RF path: `rtw8852a_chip_ops.{read,write}_rf`
    /// are `rtw89_phy_{read,write}_rf`, direct for every address.
    fn always_direct(&self) -> bool {
        self.chip == ChipId::Rtl8852A
    }
    fn direct(&self, path: u8, address: u32) -> u32 {
        // Linux `rtw89_phy_read_rf`/`rtw89_phy_write_rf` direct aperture:
        // `cr_base + rf_base_addr[path] + (addr & 0xff) * 4`. A is
        // {0xc000, 0xd000}; B/C/8851B are {0xe000, 0xf000} (8851B has one
        // path, so its path-1 base is never used).
        let base = match (self.chip, path) {
            (ChipId::Rtl8852A, 0) => 0xc000,
            (ChipId::Rtl8852A, _) => 0xd000,
            (_, 0) => 0xe000,
            (_, _) => 0xf000,
        };
        BASE + base + ((address & 255) << 2)
    }
    /// # Safety
    /// Same exclusively retained actual factory/MAC owner for this chip,
    /// full Device BAR aperture covering its last direct RF dword
    /// (A >=0x1d400, B/C >=0x1f400) and current per-transaction device
    /// authority. No concurrent RFK/table/channel/reset/PHY operation. The
    /// enclosing attempt closes packet/command DMA and retains published
    /// resources on cancellation.
    pub async unsafe fn read(
        &mut self,
        io: &mut impl Io,
        path: u8,
        address: u32,
        mask: u32,
    ) -> Result<u32, Error> {
        self.begin(path, address, mask)?;
        let mask = mask & RF_MASK;
        let result = async {
            if self.always_direct() || address & 0x10000 != 0 {
                return Ok((read(io, self.direct(path, address))? & mask) >> mask.trailing_zeros());
            }
            idle(io).await?;
            modify(io, BASE + 0x378, 0x7ff, u32::from(path) << 8 | address)?;
            io.delay_us(2).await;
            let start = io.now_us();
            loop {
                if read(io, SWSI)? & (1 << 26) != 0 {
                    break;
                }
                if io.now_us().saturating_sub(start) >= 30 {
                    return Err(Error::Timeout);
                }
                io.delay_us(1).await;
            }
            Ok((read(io, SWSI)? & mask) >> mask.trailing_zeros())
        }
        .await;
        self.end(result)
    }
    /// # Safety
    /// Same retained/current full-aperture contract as read, for this chip.
    /// Analog success means the command was issued; the next transaction
    /// checks actual busy.
    pub async unsafe fn write(
        &mut self,
        io: &mut impl Io,
        path: u8,
        address: u32,
        mask: u32,
        data: u32,
    ) -> Result<(), Error> {
        self.begin(path, address, mask)?;
        let mask = mask & RF_MASK;
        let result = async {
            if self.always_direct() || address & 0x10000 != 0 {
                modify(io, self.direct(path, address), mask, data)?;
                io.delay_us(1).await;
                return Ok(());
            }
            idle(io).await?;
            let partial = mask != RF_MASK;
            let mut data = data & RF_MASK;
            if partial {
                modify(io, BASE + 0x374, RF_MASK, mask)?;
                data = (data << mask.trailing_zeros()) & RF_MASK;
            }
            let value =
                (u32::from(partial) << 31) | (u32::from(path) << 28) | (address << 20) | data;
            modify(io, BASE + 0x370, u32::MAX, value)
        }
        .await;
        self.end(result)
    }
}
fn read(io: &mut impl Io, address: u32) -> Result<u32, Error> {
    let value = io.read32(address)?;
    if value == u32::MAX {
        Err(Error::Gone)
    } else {
        Ok(value)
    }
}
fn modify(io: &mut impl Io, address: u32, mask: u32, data: u32) -> Result<(), Error> {
    let old = read(io, address)?;
    io.write32(
        address,
        (old & !mask) | ((data << mask.trailing_zeros()) & mask),
    )
}
async fn idle(io: &mut impl Io) -> Result<(), Error> {
    let start = io.now_us();
    loop {
        // Preserve original short-circuit read ordering: W_BUSY is checked
        // before a separate R_BUSY read from the same volatile register.
        if read(io, SWSI)? & (1 << 24) == 0 && read(io, SWSI)? & (1 << 25) == 0 {
            return Ok(());
        }
        if io.now_us().saturating_sub(start) >= 30 {
            return Err(Error::Timeout);
        }
        io.delay_us(1).await;
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "rf_access/tests.rs"]
mod tests;
