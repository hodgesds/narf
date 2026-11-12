// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! One retained actual B, C or 8851B BB/gain/power/reset/RF-table preparation
//! attempt.
use super::{
    factory::Factory,
    factory_51,
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
    N51(factory_51::Calibration),
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
            Inputs::N51(_) => ChipId::Rtl8851B,
        }
    }
    /// RTL8851B: the same actual-factory qualification, from
    /// `rtw8851b_read_efuse`/`rtw8851b_read_phycap` inputs.
    pub fn from_factory_51(factory: &Factory) -> Option<Self> {
        let identity = factory.identity()?;
        let calibration = identity.calibration();
        if identity.chip() != ChipId::Rtl8851B || !calibration.valid || calibration.rfe_type == 255
        {
            return None;
        }
        Some(Self {
            rfe: calibration.rfe_type,
            cut: identity.cut(),
            inputs: Inputs::N51(factory_51::Calibration::from_factory(factory)?),
        })
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
    calibration_51: Option<factory_51::Calibration>,
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
    pub fn calibration_51(&self) -> Option<&factory_51::Calibration> {
        (self.state == State::TablesLoaded)
            .then_some(self.calibration_51.as_ref())
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
        let n51 = matches!(qualified.inputs, Inputs::N51(_));
        if n51 != (assets.chip() == ChipId::Rtl8851B) {
            return Err(Error::Profile);
        }
        // RTL8851B has one RF path (`rf_table = {radioa}`): its path-B
        // program is empty and never written or paged.
        let programs = (0..5)
            .map(|i| {
                if n51 && i == 3 {
                    return Ok(Vec::new());
                }
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
            Inputs::N51(calibration) => self.calibration_51 = Some(calibration),
        }
        bb(io, &programs[0]).await?;
        if c {
            power_units_c(io)?;
            reset_c(io).await?;
        } else if n51 {
            // rtw8851b_init_txpwr_unit writes the same SCC MAC0 values and
            // UL_TB 1T/2T offsets as rtw8852b; only bb_reset differs.
            power_units(io)?;
            reset_51(io).await?;
        } else {
            power_units(io)?;
            reset(io).await?;
        }
        // phy.c `rtw89_phy_init_rf_reg` walks `chip->rf_table[]` in order:
        // B `{radioa, radiob}`, C `{radiob, radioa}`; each table keeps its
        // own RF path for writes and the H2C page `rf_path`.
        let order: &[usize] = if c {
            &[1, 0]
        } else if n51 {
            &[0]
        } else {
            &[0, 1]
        };
        for &path in order {
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
pub(super) fn validate_bb(program: &[Pair]) -> Result<(), Error> {
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
pub(super) fn rf_pages(program: &[Pair]) -> Result<Vec<u8>, Error> {
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
pub(super) async fn bb(io: &mut impl Io, program: &[Pair]) -> Result<(), Error> {
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
/// rtw8851b.c `rtw8851b_bb_reset(PHY_0)`: R_P0_TXPW_RSTB MANON|TSSI = 1 and
/// R_P0_TSSI_TRK EN set, `rtw8851b_bb_reset_all` (S0 HW-SI trigger only, no
/// S1), then MANON|TSSI = 3 and TSSI_TRK EN cleared. Every final field is
/// read back.
async fn reset_51(io: &mut impl Io) -> Result<(), Error> {
    modify(io, 0x158dc, 0xc000_0000, 1)?;
    modify(io, 0x15818, 1 << 30, 1)?;
    modify(io, 0x11200, 0x7000_0000, 7)?;
    io.delay_us(1).await;
    modify(io, 0x10704, 2, 1)?;
    modify(io, 0x10704, 2, 0)?;
    modify(io, 0x11200, 0x7000_0000, 0)?;
    modify(io, 0x10704, 2, 1)?;
    modify(io, 0x158dc, 0xc000_0000, 3)?;
    modify(io, 0x15818, 1 << 30, 0)?;
    for (a, m, v) in [
        (0x10704, 2, 2),
        (0x11200, 0x7000_0000, 0),
        (0x158dc, 0xc000_0000, 0xc000_0000),
        (0x15818, 1 << 30, 0),
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
/// rtw8852c.c `rtw8852c_bb_sethw`: DBCC 80+80 EVM report enables,
/// `rtw8852c_bb_macid_ctrl_init(PHY_0)` (MACID power-limit table zeroed),
/// `rtw8852c_bb_gpio_init` and the post-table `R_RPL_BIAS_COMP{,1}`
/// (0x4df0/0x6df0 [7:0]) `efuse_gain.offset_base` reads, each read back.
pub(super) fn controls_c(io: &mut impl Io) -> Result<[i8; 2], Error> {
    for address in [0x10a10, 0x12a10] {
        modify(io, address, 1, 1)?;
    }
    for address in (0xd36c..=0xd568).step_by(4) {
        io.write32(address, 0)?;
    }
    gpio_c(io)?;
    for address in [0x10a10, 0x12a10] {
        if read(io, address)? & 1 != 1 {
            return Err(power::Error::Access.into());
        }
    }
    for address in (0xd36c..=0xd568).step_by(4) {
        if read(io, address)? != 0 {
            return Err(power::Error::Access.into());
        }
    }
    for (address, mask, value) in GPIO_C_STATE {
        // R_RFE_E_A2 legitimately reads all-ones; `read` would call it Gone.
        let actual = if value == u32::MAX {
            io.read32(address)?
        } else {
            read(io, address)?
        };
        if actual & mask != value {
            return Err(power::Error::Access.into());
        }
    }
    Ok([
        read(io, 0x14df0)? as u8 as i8,
        read(io, 0x16df0)? as u8 as i8,
    ])
}
/// rtw8851b.c `rtw8851b_bb_sethw`: R_P0_EN_SOUND_WO_NDP clear (path 0 only),
/// `rtw8851b_bb_macid_ctrl_init(PHY_0)`, `rtw8851b_bb_gpio_init` (path A
/// only), R_AX_PWR_NORM_FORCE1 FORCE_NTX_VALUE clear / FORCE_NTX_EN set,
/// all read back, then the post-table `efuse_gain.offset_base`
/// (R_P0_RPL1 0x49b0 [7:0]) and `rssi_base` (R_P1_RPL1 0x4a00 [7:0]).
pub(super) fn controls_51(io: &mut impl Io) -> Result<[i8; 2], Error> {
    modify(io, 0x10d7c, 2, 0)?;
    for address in (0xd36c..=0xd568).step_by(4) {
        io.write32(address, 0)?;
    }
    gpio_51(io)?;
    modify(io, 0xd260, 1 << 5, 0)?;
    modify(io, 0xd260, 1 << 6, 1)?;
    if read(io, 0x10d7c)? & 2 != 0 || read(io, 0xd260)? & 0x60 != 0x40 {
        return Err(power::Error::Access.into());
    }
    for address in (0xd36c..=0xd568).step_by(4) {
        if read(io, address)? != 0 {
            return Err(power::Error::Access.into());
        }
    }
    for (address, mask, value) in GPIO_51_STATE {
        // R_RFE_E_A2 legitimately reads all-ones; `read` would call it Gone.
        let actual = if value == u32::MAX {
            io.read32(address)?
        } else {
            read(io, address)?
        };
        if actual & mask != value {
            return Err(power::Error::Access.into());
        }
    }
    Ok([
        read(io, 0x149b0)? as u8 as i8,
        read(io, 0x14a00)? as u8 as i8,
    ])
}
/// The register state `rtw8851b_bb_gpio_init` leaves behind (R_P0_TRSW
/// 0x5868 TRSW_A set, TRSW_X/TRSW_SO_A2 clear, the eight path-A
/// `rtw8851b_bb_gpio_trsw` fields at [31:16] = 0xa9a9; SEL0/SEL32 bases and
/// the A2 RFE words).
const GPIO_51_STATE: [(u32, u32, u32); 7] = [
    (0x15868, 0xffff_00e6, 0xa9a9_0002),
    (0x15880, u32::MAX, 0x7777_7777),
    (0x15884, u32::MAX, 0x7777_7777),
    (0x10334, u32::MAX, u32::MAX),
    (0x10338, u32::MAX, 0),
    (0x1033c, u32::MAX, 0),
    (0x10340, u32::MAX, 0),
];
/// rtw8851b.c `rtw8851b_bb_gpio_init` in Linux write order.
fn gpio_51(io: &mut impl Io) -> Result<(), Error> {
    let address = 0x15868;
    let value = read(io, address)?;
    io.write32(address, value | 2)?;
    let value = read(io, address)?;
    io.write32(address, value & !4)?;
    let value = read(io, address)?;
    io.write32(address, value & !0xe0)?;
    io.write32(0x15880, 0x7777_7777)?;
    io.write32(0x15884, 0x7777_7777)?;
    io.write32(0x10334, u32::MAX)?;
    io.write32(0x10338, 0)?;
    io.write32(0x1033c, 0)?;
    io.write32(0x10340, 0)?;
    // `rtw8851b_bb_gpio_trsw(RF_PATH_A, tx_path_en, trsw_tx, trsw_rx,
    // trsw_a, trsw_b)`.
    for (tx, trsw_tx, trsw_rx, trsw_a, trsw_b) in GPIO_TRSW {
        let shift = 16 + (tx * 4 + trsw_tx * 2 + trsw_rx) * 2;
        modify(io, 0x15868, 3 << shift, (trsw_a << 1) | trsw_b)?;
    }
    Ok(())
}
/// The eight `bb_gpio_trsw` rows shared by rtw8852c.c and rtw8851b.c.
const GPIO_TRSW: [(u32, u32, u32, u32, u32); 8] = [
    (0, 0, 0, 0, 1),
    (0, 0, 1, 1, 0),
    (0, 1, 0, 1, 0),
    (0, 1, 1, 1, 0),
    (1, 0, 0, 0, 1),
    (1, 0, 1, 1, 0),
    (1, 1, 0, 1, 0),
    (1, 1, 1, 1, 0),
];
/// The register state `rtw8852c_bb_gpio_init` leaves behind (per path base
/// 0x5800/0x7800): TRSW_A set, TRSW_X/TRSW_SO_A2 clear, the eight
/// `rtw8852c_bb_gpio_trsw` 2-bit fields at [31:16] = 0xa9a9, 0x80/0x84 =
/// 0x77777777 and the PAPE/TRSW/LNAON `rtw8852c_bb_gpio_rfm` bytes 0/4/8.
const GPIO_C_STATE: [(u32, u32, u32); 12] = [
    (0x15868, 0xffff_00e6, 0xa9a9_0002),
    (0x15880, u32::MAX, 0x7777_7777),
    (0x15884, u32::MAX, 0x7777_7777),
    (0x15894, 0x00ff_ffff, 0x0008_0400),
    (0x17868, 0xffff_00e6, 0xa9a9_0002),
    (0x17880, u32::MAX, 0x7777_7777),
    (0x17884, u32::MAX, 0x7777_7777),
    (0x17894, 0x00ff_ffff, 0x0008_0400),
    (0x10334, u32::MAX, u32::MAX),
    (0x10338, u32::MAX, 0),
    (0x1033c, u32::MAX, 0),
    (0x10340, u32::MAX, 0),
];
/// rtw8852c.c `rtw8852c_bb_gpio_init` in Linux write order.
fn gpio_c(io: &mut impl Io) -> Result<(), Error> {
    for base in [0x15800, 0x17800] {
        let address = base | 0x68;
        let value = read(io, address)?;
        io.write32(address, value | 2)?;
        let value = read(io, address)?;
        io.write32(address, value & !4)?;
        let value = read(io, address)?;
        io.write32(address, value & !0xe0)?;
        io.write32(base | 0x80, 0x7777_7777)?;
        io.write32(base | 0x84, 0x7777_7777)?;
    }
    io.write32(0x10334, u32::MAX)?;
    io.write32(0x10338, 0)?;
    io.write32(0x1033c, 0)?;
    io.write32(0x10340, 0)?;
    // `rtw8852c_bb_gpio_trsw(path, tx_path_en, trsw_tx, trsw_rx, trsw, trsw_b)`.
    const TRSW: [(u32, u32, u32, u32, u32); 8] = [
        (0, 0, 0, 0, 1),
        (0, 0, 1, 1, 0),
        (0, 1, 0, 1, 0),
        (0, 1, 1, 1, 0),
        (1, 0, 0, 0, 1),
        (1, 0, 1, 1, 0),
        (1, 1, 0, 1, 0),
        (1, 1, 1, 1, 0),
    ];
    for base in [0x15868, 0x17868] {
        for (tx, trsw_tx, trsw_rx, trsw, trsw_b) in TRSW {
            let shift = 16 + (tx * 4 + trsw_tx * 2 + trsw_rx) * 2;
            modify(io, base, 3 << shift, (trsw << 1) | trsw_b)?;
        }
    }
    // `rtw8852c_bb_gpio_rfm(path, PAPE/TRSW/LNAON_RFM, 0, 0, 0, out)`.
    for base in [0x15894, 0x17894] {
        for (shift, out) in [(0, 0), (8, 4), (16, 8)] {
            modify(io, base, 0xff << shift, out)?;
        }
    }
    Ok(())
}
/// Exact AX NCTL pre-init and selected real table. Full DM/coexistence and
/// RFK orchestration must establish its correct startup position before use.
pub(super) async fn nctl(io: &mut impl Io, program: &[Pair]) -> Result<(), Error> {
    nctl_for(io, program, &NCTL_PREINIT).await
}
/// RTL8852C NCTL: phy.c `rtw89_phy_preinit_rf_nctl_ax` without the
/// RTL8852B/BT-only second `R_IOQ_IQK_DPK |= 0x2`, then the selected
/// firmware NCTL table (`rtw8852c_chip_info.nctl_post_table` is NULL).
pub(super) async fn nctl_c(io: &mut impl Io, program: &[Pair]) -> Result<(), Error> {
    nctl_for(io, program, &NCTL_PREINIT[..4]).await
}
/// RTL8922A NCTL: phy.c `rtw89_phy_preinit_rf_nctl_ax` with the P1 reset
/// (the chip is not RTL8851B) and no RTL8852B/BT second `R_IOQ_IQK_DPK`
/// write, then the selected firmware NCTL table;
/// `rtw8922a_chip_info.nctl_post_table` is NULL (`rtw8922a.c:3246`), so
/// there is no post-table step. (Shared with the BE table-application
/// owner, `radio_be`; the 8852A sibling lane owns the A paths.)
pub(super) async fn nctl_be(io: &mut impl Io, program: &[Pair]) -> Result<(), Error> {
    nctl_for(io, program, &NCTL_PREINIT[..4]).await
}
/// RTL8851B NCTL: phy.c `rtw89_phy_preinit_rf_nctl_ax` with the one-path
/// skips (no `R_P1_PATH_RST`, no RTL8852B/BT second `R_IOQ_IQK_DPK`), the
/// selected firmware NCTL table, then `rtw8851b_chip_info.nctl_post_table`
/// (`rtw8851b_nctl_post_defs`, rtw8851b_rfk_table.c) through
/// `rtw89_rfk_parser`, each WM field read back.
pub(super) async fn nctl_51(io: &mut impl Io, program: &[Pair]) -> Result<(), Error> {
    nctl_for(io, program, &NCTL_PREINIT[..3]).await?;
    for (address, mask, value) in NCTL_POST_51 {
        modify(io, 0x10000 + address, mask, value)?;
    }
    for (address, mask, value) in NCTL_POST_51 {
        if read(io, 0x10000 + address)? & mask != (value << mask.trailing_zeros()) & mask {
            return Err(power::Error::Access.into());
        }
    }
    Ok(())
}
/// phy.c `rtw89_phy_preinit_rf_nctl_ax` set-bit writes in Linux order:
/// R_IOQ_IQK_DPK, R_GNT_BT_WGT_EN, R_P0_PATH_RST, R_P1_PATH_RST (not
/// RTL8851B) and the RTL8852B/BT-only second R_IOQ_IQK_DPK.
const NCTL_PREINIT: [(u32, u32); 5] = [
    (0x10c60, 3),
    (0x10c6c, 1),
    (0x158ac, 0x08000000),
    (0x178ac, 0x08000000),
    (0x10c60, 2),
];
/// rtw8851b_rfk_table.c `rtw8851b_nctl_post_defs` (all RTW89_DECL_RFK_WM,
/// PHY-relative addresses), verbatim including the path-B literals.
pub(super) const NCTL_POST_51: [(u32, u32, u32); 17] = [
    (0x5864, 0x18000000, 0x3),
    (0x7864, 0x18000000, 0x3),
    (0x030c, 0xff000000, 0x13),
    (0x032c, 0xffff0000, 0x0041),
    (0x12b8, 0x10000000, 0x1),
    (0x2008, 0x01ffffff, 0x00fffff),
    (0x0c60, 0x00000003, 0x3),
    (0x0c6c, 0x00000001, 0x1),
    (0x58ac, 0x08000000, 0x1),
    (0x78ac, 0x08000000, 0x1),
    (0x0730, 0x00003800, 0x7),
    (0x2730, 0x00003800, 0x7),
    (0x0c7c, 0x00e00000, 0x1),
    (0x58c0, 0x0001ffff, 0x00000),
    (0x78c0, 0x0001ffff, 0x00000),
    (0x58fc, 0x3f000000, 0x00),
    (0x78fc, 0x3f000000, 0x00),
];
async fn nctl_for(io: &mut impl Io, program: &[Pair], preinit: &[(u32, u32)]) -> Result<(), Error> {
    validate_bb(program)?;
    for &(address, mask) in preinit {
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
