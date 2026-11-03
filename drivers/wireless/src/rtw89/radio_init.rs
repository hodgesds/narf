// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! One retained actual B or C BB/gain/power/reset/RF-table preparation attempt.
use super::{
    factory::Factory,
    factory_b::Calibration,
    factory_c,
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
/// The chip-specific factory calibration that qualified this attempt.
#[derive(Clone, Copy)]
enum Inputs {
    B(Calibration),
    C(factory_c::Calibration),
}
#[derive(Clone, Copy)]
pub(super) struct Qualified {
    rfe: u8,
    cut: u8,
    inputs: Inputs,
}
impl Qualified {
    pub fn chip(&self) -> ChipId {
        match self.inputs {
            Inputs::B(_) => ChipId::Rtl8852B,
            Inputs::C(_) => ChipId::Rtl8852C,
        }
    }
    /// RTL8852C: the same actual-factory qualification as B, from
    /// `rtw8852c_read_efuse`/`rtw8852c_read_phycap` inputs.
    pub fn from_factory_c(factory: &Factory) -> Option<Self> {
        let identity = factory.identity()?;
        let calibration = identity.calibration();
        if identity.chip() != ChipId::Rtl8852C || !calibration.valid || calibration.rfe_type == 255
        {
            return None;
        }
        Some(Self {
            rfe: calibration.rfe_type,
            cut: identity.cut(),
            inputs: Inputs::C(factory_c::Calibration::from_factory(factory)?),
        })
    }
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
            inputs: Inputs::B(Calibration::from_factory(factory)?),
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
    calibration_c: Option<factory_c::Calibration>,
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
    pub fn calibration_c(&self) -> Option<&factory_c::Calibration> {
        (self.state == State::TablesLoaded)
            .then_some(self.calibration_c.as_ref())
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
        if assets.chip() != qualified.chip() {
            return Err(Error::Profile);
        }
        let pages = [rf_pages(&programs[2])?, rf_pages(&programs[3])?];
        let c = matches!(qualified.inputs, Inputs::C(_));
        // phy.c `rtw89_phy_config_bb_gain_ax` is the generation decoder for
        // both chips (8 gain bands cover C's 6GHz L/M/H/UH).
        self.gain = Some(Gain::decode(&programs[1], qualified.rfe).map_err(Error::Gain)?);
        match qualified.inputs {
            Inputs::B(calibration) => self.calibration = Some(calibration),
            Inputs::C(calibration) => self.calibration_c = Some(calibration),
        }
        bb(io, &programs[0]).await?;
        if c {
            power_units_c(io)?;
            reset_c(io).await?;
        } else {
            power_units(io)?;
            reset(io).await?;
        }
        // phy.c `rtw89_phy_init_rf_reg` walks `chip->rf_table[]` in order:
        // B `{radioa, radiob}`, C `{radiob, radioa}`; each table keeps its
        // own RF path for writes and the H2C page `rf_path`.
        let order: [usize; 2] = if c { [1, 0] } else { [0, 1] };
        for path in order {
            let program = programs[2 + path].as_slice();
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
/// `phy.c::rtw89_phy_init_rf_reg(noio = true)`: the RF path A/B
/// firmware register pages only (no RF write), rebuilt from the same
/// retained signed tables for a freshly downloaded image.
pub(super) fn noio_pages(qualified: Qualified, assets: &Assets) -> Result<[Vec<u8>; 2], Error> {
    let page = |index: usize| -> Result<Vec<u8>, Error> {
        let program = radio_table::program(
            assets.table(index).ok_or(Error::Profile)?,
            qualified.rfe,
            qualified.cut,
        )
        .map_err(Error::Table)?;
        rf_pages(&program)
    };
    Ok([page(2)?, page(3)?])
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
/// rtw8852c.c `rtw8852c_init_txpwr_unit(RTW89_PHY_0)`: UL/coex power CRs,
/// `rtw8852c_set_txpwr_ul_tb_offset(0, MAC_0)` (V1 byte masks, no UL_TB
/// enable bit) and `rtw8852c_init_tssi_ctrl` with the flat band-edge/fast
/// mode configuration (`rtw89_8852c_tssi_dbw_table` FLAT row is all zero).
fn power_units_c(io: &mut impl Io) -> Result<(), Error> {
    const CTRL_INI: [(u32, u32); 6] = [
        (0xd938, 0x00010100),
        (0xd93c, 0x0500d500),
        (0xd940, 0x00000500),
        (0xd944, 0x00000005),
        (0xd94c, 0x00220000),
        (0xd950, 0x00030000),
    ];
    const BANDEDGE_FLAT: [(u32, u32); 15] = [
        (0xd91c, 0xff000000),
        (0xd920, 0xff),
        (0xd920, 0xff00),
        (0xd920, 0xff0000),
        (0xd920, 0xff000000),
        (0xd924, 0xff),
        (0xd924, 0xff00),
        (0xd914, 0xff000000),
        (0xd918, 0xff),
        (0xd918, 0xff00),
        (0xd918, 0xff0000),
        (0xd918, 0xff000000),
        (0xd91c, 0xff),
        (0xd91c, 0xff00),
        (0xd91c, 0xff0000),
    ];
    const FASTMODE_FLAT: [(u32, u32); 4] = [
        (0xd934, 0xff0000),
        (0xd934, 0xff000000),
        (0xd938, 0xff),
        (0xd934, 0xff00),
    ];
    io.write32(0xd248, 0x07763333)?;
    io.write32(0xd220, 0x01ebf000)?;
    io.write32(0xd240, 0x0002f8ff)?;
    // val_1t = 0 << 2; val_2t = max(0 - 3, -32) << 2 = -12.
    for i in 0..4 {
        modify(io, 0xd28c, 0xff << (8 * i), 0)?;
        modify(io, 0xd290, 0xff << (8 * i), 0xf4)?;
    }
    for address in (0xd908..=0xd95c).step_by(4) {
        io.write32(address, 0)?;
    }
    for (address, value) in CTRL_INI {
        io.write32(address, value)?;
    }
    for (address, mask) in BANDEDGE_FLAT {
        modify(io, address, mask, 0)?;
    }
    modify(io, 0xd94c, 0xc000_0000, 0)?;
    for (address, mask) in FASTMODE_FLAT {
        modify(io, address, mask, 0)?;
    }
    for (address, value) in [
        (0xd248, 0x07763333),
        (0xd220, 0x01ebf000),
        (0xd240, 0x0002f8ff),
        (0xd28c, 0),
        (0xd290, 0xf4f4_f4f4),
    ] {
        if read(io, address)? != value {
            return Err(power::Error::Access.into());
        }
    }
    for address in (0xd908..=0xd95c).step_by(4) {
        let expected = CTRL_INI
            .iter()
            .find(|(a, _)| *a == address)
            .map_or(0, |(_, v)| *v);
        if read(io, address)? != expected {
            return Err(power::Error::Access.into());
        }
    }
    Ok(())
}
/// rtw8852c.c `rtw8852c_bb_reset_all(RTW89_PHY_0)` (via phy.c
/// `rtw89_phy_bb_reset`): HW-SI trigger hold around the async BB reset,
/// without B's TSSI-tracking pause.
async fn reset_c(io: &mut impl Io) -> Result<(), Error> {
    modify(io, 0x11200, 0x70000000, 7)?;
    modify(io, 0x13200, 0x70000000, 7)?;
    io.delay_us(1).await;
    modify(io, 0x10704, 2, 1)?;
    modify(io, 0x10704, 2, 0)?;
    modify(io, 0x11200, 0x70000000, 0)?;
    modify(io, 0x13200, 0x70000000, 0)?;
    modify(io, 0x10704, 2, 1)?;
    for (a, m, v) in [
        (0x10704, 2, 2),
        (0x11200, 0x70000000, 0),
        (0x13200, 0x70000000, 0),
    ] {
        if read(io, a)? & m != v {
            return Err(power::Error::Access.into());
        }
    }
    Ok(())
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
