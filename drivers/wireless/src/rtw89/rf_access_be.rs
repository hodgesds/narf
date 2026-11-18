// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A RF-v2 HWSI/direct transactions (phy.c::{read,write}_rf_v2),
//! phy_be.c CR base0x20000 and rtw8922a.c rf_base_addr{0xe000,0xf000}.
//! Source success for an analog write is issuance; the next operation checks
//! actual busy. No DMA, calibration, ordinary-response or RF grant is minted.
use super::power::{Error, Io};
const BASE: u32 = 0x20000;
const RF_MASK: u32 = 0xfffff;
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
    pub(super) fn state(&self) -> State {
        self.state
    }
    fn begin(&mut self, path: u8, address: u32, mask: u32) -> Result<(), Error> {
        if self.state != State::Idle {
            return Err(Error::Terminal);
        }
        if path >= 2 || address & !0x100ff != 0 || mask == 0 || mask & !RF_MASK != 0 {
            return Err(Error::Unsupported);
        }
        self.state = State::Busy;
        Ok(())
    }
    fn end<T>(&mut self, r: Result<T, Error>) -> Result<T, Error> {
        self.state = if r.is_ok() {
            State::Idle
        } else {
            State::Terminal
        };
        r
    }
    /// # Safety
    /// Exclusive original RTL8922A qualified radio/reset owner, current signed
    /// calibration/RF/device authority around EACH actual Io operation and a
    /// complete live Device BAR (direct RF through0x2f3fc). No other radio/IRQ
    /// producer. Enclosing cancellation terminalizes and retains DMA ownership.
    pub(super) async unsafe fn read(
        &mut self,
        io: &mut impl Io,
        path: u8,
        address: u32,
        mask: u32,
    ) -> Result<u32, Error> {
        self.begin(path, address, mask)?;
        let r = async {
            let raw = if address & 0x10000 != 0 {
                read(io, direct(path, address))?
            } else {
                read_full(io, path, address).await?
            };
            Ok((raw & mask) >> mask.trailing_zeros())
        }
        .await;
        self.end(r)
    }
    /// # Safety
    /// Same original current-qualified RF-v2/full-aperture contract as read.
    /// This API is not wired into the closed native bootstrap without RFK and
    /// full-program qualification; a legacy N22A v1 record cannot enable it.
    pub(super) async unsafe fn write(
        &mut self,
        io: &mut impl Io,
        path: u8,
        address: u32,
        mask: u32,
        data: u32,
    ) -> Result<(), Error> {
        self.begin(path, address, mask)?;
        let r = async {
            if address & 0x10000 != 0 {
                modify(io, direct(path, address), mask, data)?;
                io.delay_us(1).await;
                return Ok(());
            }
            let full = if mask == RF_MASK {
                data & RF_MASK
            } else {
                let old = read_full(io, path, address).await?;
                (old & !mask) | ((data << mask.trailing_zeros()) & mask)
            };
            let status = BASE + [0x2c24, 0x2d24][usize::from(path)];
            wait(io, status, 1 << 29, 0).await?;
            let port = BASE + [0x2ae0, 0x2be0][usize::from(path)];
            io.write32(port, (address & 0xff) | ((full << 8) & 0x0fff_ff00))
        }
        .await;
        self.end(r)
    }
}
fn direct(path: u8, address: u32) -> u32 {
    BASE + [0xe000, 0xf000][usize::from(path)] + ((address & 0xff) << 2)
}
fn read(io: &mut impl Io, a: u32) -> Result<u32, Error> {
    let v = io.read32(a)?;
    if v == u32::MAX {
        Err(Error::Gone)
    } else {
        Ok(v)
    }
}
fn modify(io: &mut impl Io, a: u32, mask: u32, value: u32) -> Result<(), Error> {
    let old = read(io, a)?;
    io.write32(a, (old & !mask) | ((value << mask.trailing_zeros()) & mask))
}
async fn wait(io: &mut impl Io, a: u32, mask: u32, want: u32) -> Result<(), Error> {
    let start = io.now_us();
    loop {
        if read(io, a)? & mask == want {
            return Ok(());
        }
        if io.now_us().saturating_sub(start) >= 3800 {
            return Err(Error::Timeout);
        }
        io.delay_us(1).await;
    }
}
async fn read_full(io: &mut impl Io, path: u8, address: u32) -> Result<u32, Error> {
    let control = BASE + [0x2adc, 0x2bdc][usize::from(path)];
    let status = BASE + [0x2c24, 0x2d24][usize::from(path)];
    modify(io, control, 7, 1)?;
    wait(io, status, 1 << 29, 0).await?;
    modify(io, control, 0xff0, address)?;
    modify(io, control, 4, 1)?;
    io.delay_us(2).await;
    match wait(io, status, 1 << 31, 1 << 31).await {
        Ok(()) => {
            let value = read(io, status)? & RF_MASK;
            modify(io, control, 3, 0)?;
            Ok(value)
        }
        // Source out: on RDONE timeout only, clear POLL control while the
        // same current-qualified Io remains accessible. Access failure never
        // triggers a speculative cleanup effect, sentinel read or fake Ok.
        Err(Error::Timeout) => {
            modify(io, control, 3, 0)?;
            Err(Error::Timeout)
        }
        Err(e) => Err(e),
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "rf_access_be_tests.rs"]
mod tests;
