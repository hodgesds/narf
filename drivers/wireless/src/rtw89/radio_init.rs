// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! One retained actual B BB/gain/power/reset/RF-table preparation attempt.
use super::{
    factory::Factory,
    factory_b::Calibration,
    mac::ChipId,
    power::{self, Io},
    radio_assets::Assets,
    radio_gain::{self, Gain},
    radio_table::{self, Pair},
};
use alloc::vec::Vec;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Register(power::Error),
    Table(radio_table::Error),
    Gain(radio_gain::Error),
    Memory,
    Profile,
    Terminal,
}
impl From<power::Error> for Error {
    fn from(e: power::Error) -> Self {
        Self::Register(e)
    }
}
pub(super) trait Interface: Io {
    async fn radio_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), Error>;
    /// The exact firmware RF page command, including actual runtime H2C seq.
    /// Success means native transport consumption, never execution receipt.
    async fn radio_page(&mut self, path: u8, page: u8, bytes: &[u8]) -> Result<(), Error>;
}
#[derive(Clone, Copy)]
pub(super) struct Qualified {
    rfe: u8,
    cut: u8,
    calibration: Calibration,
}
impl Qualified {
    pub fn from_factory(factory: &Factory) -> Option<Self> {
        let identity = factory.identity()?;
        let calibration = identity.calibration();
        if identity.chip() != ChipId::Rtl8852B || !calibration.valid || calibration.rfe_type == 255
        {
            return None;
        }
        Some(Self {
            rfe: calibration.rfe_type,
            cut: identity.cut(),
            calibration: Calibration::from_factory(factory)?,
        })
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Preparing,
    TablesLoaded,
}
#[derive(Default)]
pub(super) struct Init {
    state: State,
    gain: Option<Gain>,
    calibration: Option<Calibration>,
}
impl Init {
    pub fn state(&self) -> State {
        self.state
    }
    pub fn gain(&self) -> Option<&Gain> {
        (self.state == State::TablesLoaded)
            .then_some(self.gain.as_ref())
            .flatten()
    }
    pub fn calibration(&self) -> Option<&Calibration> {
        (self.state == State::TablesLoaded)
            .then_some(self.calibration.as_ref())
            .flatten()
    }
    /// # Safety
    /// Same actual B factory/MAC/RX Native, full PHY aperture, current authority
    /// and exclusive radio/reset/power ownership. Outer Startup terminalizes
    /// and retains all published command/RX DMA on cancellation or failure.
    pub async unsafe fn prepare(
        &mut self,
        io: &mut impl Interface,
        qualified: Qualified,
        assets: &Assets,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Preparing;
        let programs = (0..5)
            .map(|i| {
                radio_table::program(
                    assets.table(i).ok_or(Error::Profile)?,
                    qualified.rfe,
                    qualified.cut,
                )
                .map_err(Error::Table)
            })
            .collect::<Result<Vec<_>, _>>()?;
        // Validate every pair and decode all gain state before first PHY write.
        for i in [0, 4] {
            validate_bb(&programs[i])?;
        }
        let pages = [rf_pages(&programs[2])?, rf_pages(&programs[3])?];
        self.gain = Some(Gain::decode(&programs[1], qualified.rfe).map_err(Error::Gain)?);
        self.calibration = Some(qualified.calibration);
        bb(io, &programs[0]).await?;
        power_units(io)?;
        reset(io).await?;
        for (path, program) in [programs[2].as_slice(), programs[3].as_slice()]
            .into_iter()
            .enumerate()
        {
            for &Pair(address, value) in program {
                if address == 0xfe {
                    io.delay_us(50_000).await;
                } else {
                    io.radio_write(path as u8, address, 0xfffff, value).await?;
                }
            }
            for (page, bytes) in pages[path].chunks(2000).enumerate() {
                io.radio_page(path as u8, page as u8, bytes).await?;
            }
        }
        self.state = State::TablesLoaded;
        Ok(())
    }
}
fn validate_bb(program: &[Pair]) -> Result<(), Error> {
    for &Pair(address, data) in program {
        if (0xf9..=0xfe).contains(&address) || data == 0xbabecafe {
            continue;
        }
        if address > 0xffff || address & 3 != 0 {
            return Err(Error::Profile);
        }
    }
    Ok(())
}
fn rf_pages(program: &[Pair]) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    for &Pair(address, data) in program {
        if address == 0xfe {
            continue;
        }
        if address & !0x100ff != 0 {
            return Err(Error::Profile);
        }
        if address >= 0x100 {
            if bytes.len() >= 3 * 500 * 4 {
                return Err(Error::Profile);
            }
            bytes.try_reserve(4).map_err(|_| Error::Memory)?;
            bytes.extend_from_slice(&((address << 20) | data).to_le_bytes());
        }
    }
    Ok(bytes)
}
async fn bb(io: &mut impl Io, program: &[Pair]) -> Result<(), Error> {
    for &Pair(address, data) in program {
        let delay = match address {
            0xfe => 50_000,
            0xfd => 5_000,
            0xfc => 1_000,
            0xfb => 50,
            0xfa => 5,
            0xf9 => 1,
            _ => 0,
        };
        if delay != 0 {
            io.delay_us(delay).await;
        } else if data != 0xbabecafe {
            io.write32(0x10000 + address, data)?;
        }
    }
    Ok(())
}
fn read(io: &mut impl Io, address: u32) -> Result<u32, power::Error> {
    let value = io.read32(address)?;
    if value == u32::MAX {
        Err(power::Error::Gone)
    } else {
        Ok(value)
    }
}
fn modify(io: &mut impl Io, address: u32, mask: u32, value: u32) -> Result<(), power::Error> {
    let old = read(io, address)?;
    io.write32(
        address,
        (old & !mask) | ((value << mask.trailing_zeros()) & mask),
    )
}
fn power_units(io: &mut impl Io) -> Result<(), Error> {
    // Actual SCC MAC0 TX-power CRs, without the PHY aperture offset.
    io.write32(0xd248, 0x07763333)?;
    io.write32(0xd220, 0x01ebf000)?;
    io.write32(0xd240, 0x0002f8ff)?;
    modify(io, 0xd288, 1 << 31, 1)?;
    modify(io, 0xd28c, 31, 0)?;
    modify(io, 0xd290, 31, (-3i8) as u8 as u32)?;
    for (a, v, m) in [
        (0xd248, 0x07763333, u32::MAX),
        (0xd220, 0x01ebf000, u32::MAX),
        (0xd240, 0x0002f8ff, u32::MAX),
        (0xd288, 1 << 31, 1 << 31),
        (0xd28c, 0, 31),
        (0xd290, 29, 31),
    ] {
        if read(io, a)? & m != v {
            return Err(power::Error::Access.into());
        }
    }
    Ok(())
}
async fn reset(io: &mut impl Io) -> Result<(), Error> {
    for a in [0x58dc, 0x5818, 0x78dc, 0x7818] {
        modify(io, 0x10000 + a, 1 << 30, 1)?;
    }
    modify(io, 0x11200, 0x70000000, 7)?;
    modify(io, 0x13200, 0x70000000, 7)?;
    io.delay_us(1).await;
    modify(io, 0x10704, 2, 1)?;
    modify(io, 0x10704, 2, 0)?;
    modify(io, 0x11200, 0x70000000, 0)?;
    modify(io, 0x13200, 0x70000000, 0)?;
    modify(io, 0x10704, 2, 1)?;
    for a in [0x58dc, 0x5818, 0x78dc, 0x7818] {
        modify(io, 0x10000 + a, 1 << 30, 0)?;
    }
    for (a, m, v) in [
        (0x10704, 2, 2),
        (0x11200, 0x70000000, 0),
        (0x13200, 0x70000000, 0),
        (0x158dc, 1 << 30, 0),
        (0x15818, 1 << 30, 0),
        (0x178dc, 1 << 30, 0),
        (0x17818, 1 << 30, 0),
    ] {
        if read(io, a)? & m != v {
            return Err(power::Error::Access.into());
        }
    }
    Ok(())
}
/// Exact B bb_sethw prefix. Keep the actual post-table RPL bases for later
/// factory/channel gain compensation. This does not stand in for full DM.
pub(super) fn controls(io: &mut impl Io) -> Result<[i8; 2], Error> {
    for address in [0x10d7c, 0x12d7c] {
        modify(io, address, 2, 0)?;
    }
    for address in (0xd36c..=0xd568).step_by(4) {
        io.write32(address, 0)?;
    }
    for address in [0x10d7c, 0x12d7c] {
        if read(io, address)? & 2 != 0 {
            return Err(power::Error::Access.into());
        }
    }
    for address in (0xd36c..=0xd568).step_by(4) {
        if read(io, address)? != 0 {
            return Err(power::Error::Access.into());
        }
    }
    Ok([
        read(io, 0x149b0)? as u8 as i8,
        read(io, 0x14a00)? as u8 as i8,
    ])
}
/// Exact AX NCTL pre-init and selected real table. Full DM/coexistence and
/// RFK orchestration must establish its correct startup position before use.
pub(super) async fn nctl(io: &mut impl Io, program: &[Pair]) -> Result<(), Error> {
    validate_bb(program)?;
    for (address, mask) in [
        (0x10c60, 3),
        (0x10c6c, 1),
        (0x158ac, 0x08000000),
        (0x178ac, 0x08000000),
        (0x10c60, 2),
    ] {
        let value = read(io, address)?;
        io.write32(address, value | mask)?;
    }
    io.write32(0x18000, 8)?;
    let start = io.now_us();
    loop {
        io.write32(0x18080, 4)?;
        io.delay_us(1).await;
        if read(io, 0x18080)? == 4 {
            break;
        }
        if io.now_us().saturating_sub(start) >= 1000 {
            return Err(power::Error::Timeout.into());
        }
        io.delay_us(10).await;
    }
    bb(io, program).await
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_init/tests.rs"]
mod tests;
