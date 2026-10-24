// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Real RTL8852B RF v1 SWSI/direct transactions, separate from PCIe PHY MDIO.
//! Linux phy.c::{read,write}_rf_v1 and phy_gen_ax.cr_base=0x10000.
use super::power::{Error, Io};
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
#[derive(Default)]
pub(super) struct Rf {
    state: State,
}
impl Rf {
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
    /// # Safety
    /// Same exclusively retained actual B factory/MAC owner, full >=0x1f400
    /// Device BAR aperture and current per-transaction device authority. No
    /// concurrent RFK/table/channel/reset/PHY operation. The enclosing attempt
    /// closes packet/command DMA and retains published resources on cancellation.
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
            if address & 0x10000 != 0 {
                return Ok((read(io, direct(path, address))? & mask) >> mask.trailing_zeros());
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
    /// Same retained/current full-aperture B contract as read. Analog success
    /// means the command was issued; the next transaction checks actual busy.
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
            if address & 0x10000 != 0 {
                modify(io, direct(path, address), mask, data)?;
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
fn direct(path: u8, address: u32) -> u32 {
    BASE + if path == 0 { 0xe000 } else { 0xf000 } + ((address & 255) << 2)
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
