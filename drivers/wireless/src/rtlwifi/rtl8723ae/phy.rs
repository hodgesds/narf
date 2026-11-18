// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2009-2012 Realtek Corporation.
//! RTL8723AE MAC/BB/RF tables, original values and RF channel primitives.
//!
//! Linux `rtl8723ae/{phy,rf}.c` uses `rtl8723com` BB/LSSI helpers,
//! source-identical to the retained BE helpers re-exported below. AE has
//! different tables and BB power-on writes; no BE condition walker runs.
//! A qualified `Version` is always 1T1R, so 1T2R/2T branches are absent.
use super::{tables, version::Version};
/// `store_pwrindex_diffrate_offset`: same sixteen-register/mask mapping,
/// group-end trigger and MAX_PG_GROUP as the 92C source. AE RF6052 reads
/// this store, unlike the 92C's separate unused `mcs_offset` path.
pub use crate::rtlwifi::rtl8192ce::phy::PgStore;
pub use crate::rtlwifi::rtl8723be::phy::{
    get_bb, get_rf, rf_serial_read, rf_serial_write, set_bb, set_rf, Path, B3WIREADDREAALENGTH,
    B3WIREDATALENGTH, BRFSI_RFENV, MASKDWORD, RFPGA0_XA_HSSIPARAMETER2, RFREG_OFFSET_MASK,
    RF_CHNLBW,
};
use crate::rtlwifi::{firmware_transport::Io, prepare::Error};
use alloc::boxed::Box;

const REG_SYS_FUNC_EN: u16 = 0x0002;
const REG_RF_CTRL: u16 = 0x001f;
const REG_AFE_XTAL_CTRL: u16 = 0x0024;
const REG_AFE_PLL_CTRL: u16 = 0x0028;
const REG_BWOPMODE: u16 = 0x0603;
const REG_RRSR: u16 = 0x0440;
const RFPGA0_RFMOD: u16 = 0x0800;
const RFPGA1_RFMOD: u16 = 0x0900;
const RFPGA0_ANALOGPARAMETER2: u16 = 0x0884;
const RF_RX_G1: u32 = 0x1a;

/// Source table delay tokens. PHY/PG walkers still process the row after
/// its delay; RF tokens skip the RF write. Shipped PHY rows have none.
pub const fn addr_delay_us(addr: u32) -> Option<u64> {
    match addr {
        0xfe => Some(50_000),
        0xfd => Some(5_000),
        0xfc => Some(1_000),
        0xfb => Some(50),
        0xfa => Some(5),
        0xf9 => Some(1),
        _ => None,
    }
}

pub fn mac_config(io: &impl Io) -> Result<(), Error> {
    for pair in tables::MAC.chunks_exact(2) {
        io.write8(
            u16::try_from(pair[0]).map_err(|_| Error::Descriptor)?,
            pair[1] as u8,
        )?;
    }
    io.write8(0x04ca, 0x0a)?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub cck_high_power: bool,
    pub pg: Box<PgStore>,
}

pub async fn bb_config(io: &impl Io) -> Result<Report, Error> {
    let value = io.read8(REG_AFE_PLL_CTRL)?;
    io.delay_us(2).await;
    io.write8(REG_AFE_PLL_CTRL, value | 2)?;
    io.delay_us(2).await;
    io.write8(REG_AFE_PLL_CTRL + 1, 0xff)?;
    io.delay_us(2).await;
    let value = io.read8(REG_SYS_FUNC_EN)?;
    io.write8(REG_SYS_FUNC_EN, value | 3)?;
    let value = io.read8(REG_AFE_XTAL_CTRL + 1)?;
    io.write8(REG_AFE_XTAL_CTRL + 1, value & !(1 << 6))?;
    let value = io.read8(REG_AFE_XTAL_CTRL + 2)?;
    io.write8(REG_AFE_XTAL_CTRL + 2, value & !(1 << 4))?;
    io.write8(REG_RF_CTRL, 7)?;
    for pair in tables::PHY_REG_1T.chunks_exact(2) {
        if let Some(us) = addr_delay_us(pair[0]) {
            io.delay_us(us).await;
        }
        set_bb(
            io,
            u16::try_from(pair[0]).map_err(|_| Error::Descriptor)?,
            MASKDWORD,
            pair[1],
        )?;
        io.delay_us(1).await;
    }
    // Provisioned adapters always take the PG branch. The shipped PG
    // table has no delays; retain its exact group storage without TXAGC IO.
    let pg = Box::new(PgStore::from_pg(&tables::PHY_REG_PG)?);
    for pair in tables::AGCTAB_1T.chunks_exact(2) {
        set_bb(
            io,
            u16::try_from(pair[0]).map_err(|_| Error::Descriptor)?,
            MASKDWORD,
            pair[1],
        )?;
        io.delay_us(1).await;
    }
    let cck_high_power = get_bb(io, RFPGA0_XA_HSSIPARAMETER2, 0x200)? != 0;
    Ok(Report { cck_high_power, pg })
}

pub async fn rf_config(io: &impl Io) -> Result<(), Error> {
    let regs = Path::A.regs();
    let saved = get_bb(io, regs.rfintfs, BRFSI_RFENV)?;
    set_bb(io, regs.rfintfe, BRFSI_RFENV << 16, 1)?;
    io.delay_us(1).await;
    set_bb(io, regs.rfintfo, BRFSI_RFENV, 1)?;
    io.delay_us(1).await;
    set_bb(io, regs.rfhssi_para2, B3WIREADDREAALENGTH, 0)?;
    io.delay_us(1).await;
    set_bb(io, regs.rfhssi_para2, B3WIREDATALENGTH, 0)?;
    io.delay_us(1).await;
    for pair in tables::RADIOA_1T.chunks_exact(2) {
        if let Some(us) = addr_delay_us(pair[0]) {
            io.delay_us(us).await;
        } else {
            rf_serial_write(io, Path::A, pair[0], pair[1])?;
            io.delay_us(1).await;
        }
    }
    set_bb(io, regs.rfintfs, BRFSI_RFENV, saved)
}

pub async fn umc_fixups(io: &impl Io, version: Version) -> Result<(), Error> {
    if version.is_umc_a_cut() {
        set_rf(io, Path::A, 0x1a, MASKDWORD, 0x30255).await?;
        set_rf(io, Path::A, 0x1b, MASKDWORD, 0x50a00).await?;
    } else if version.is_umc_b_cut() {
        for (reg, value) in [
            (0x0c, 0x894ae),
            (0x0a, 0x1af31),
            (0x15, 0x8f425),
            (0x26, 0x4f200),
            (0x1e, 0x44053),
            (0x1f, 0x80201),
        ] {
            set_rf(io, Path::A, reg, MASKDWORD, value).await?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Original {
    pub initial_gain: [u8; 4],
    pub framesync: u8,
    pub framesync_c34: u32,
}

/// `rtl8723e_phy_get_hw_reg_originalvalue`.
pub fn original(io: &impl Io) -> Result<Original, Error> {
    Ok(Original {
        initial_gain: [
            get_bb(io, 0x0c50, 0xff)? as u8,
            get_bb(io, 0x0c58, 0xff)? as u8,
            get_bb(io, 0x0c60, 0xff)? as u8,
            get_bb(io, 0x0c68, 0xff)? as u8,
        ],
        framesync: get_bb(io, 0x0c38, 0xff)? as u8,
        framesync_c34: get_bb(io, 0x0c34, MASKDWORD)?,
    })
}

/// AE `hw_init` snapshots both paths even though the device is 1T1R.
pub async fn read_chnlval(io: &impl Io) -> Result<[u32; 2], Error> {
    Ok([
        get_rf(io, Path::A, RF_CHNLBW, RFREG_OFFSET_MASK).await?,
        get_rf(io, Path::B, RF_CHNLBW, RFREG_OFFSET_MASK).await?,
    ])
}

pub fn enable_modulation(io: &impl Io) -> Result<(), Error> {
    set_bb(io, RFPGA0_RFMOD, 1 << 24, 1)?;
    set_bb(io, RFPGA0_RFMOD, 1 << 25, 1)?;
    set_bb(io, RFPGA0_ANALOGPARAMETER2, 1 << 10, 1)
}

/// `rtl8723e_phy_set_bw_mode_callback` plus RF6052 bandwidth. A caller
/// must hold the signed operating-point authority; this grants none.
pub async fn set_bw_mode(
    io: &impl Io,
    chnlval: &mut u32,
    forty: bool,
    prime_sc: u8,
) -> Result<(), Error> {
    if (forty && !matches!(prime_sc, 1 | 2)) || (!forty && prime_sc != 0) {
        return Err(Error::State);
    }
    let bw = io.read8(REG_BWOPMODE)?;
    let rsc = io.read8(REG_RRSR + 2)?;
    if forty {
        io.write8(REG_BWOPMODE, bw & !4)?;
        io.write8(REG_RRSR + 2, (rsc & 0x90) | (prime_sc << 5))?;
        set_bb(io, RFPGA0_RFMOD, 1, 1)?;
        set_bb(io, RFPGA1_RFMOD, 1, 1)?;
        set_bb(io, 0x0a00, 0x10, u32::from(prime_sc >> 1))?;
        set_bb(io, 0x0d00, 0xc00, u32::from(prime_sc))?;
        set_bb(io, RFPGA0_ANALOGPARAMETER2, 1 << 10, 0)?;
        set_bb(io, 0x0818, 3 << 26, if prime_sc == 1 { 2 } else { 1 })?;
    } else {
        io.write8(REG_BWOPMODE, bw | 4)?;
        set_bb(io, RFPGA0_RFMOD, 1, 0)?;
        set_bb(io, RFPGA1_RFMOD, 1, 0)?;
        set_bb(io, RFPGA0_ANALOGPARAMETER2, 1 << 10, 1)?;
    }
    let next = (*chnlval & 0xffff_f3ff) | if forty { 0 } else { 0x400 };
    rf_serial_write(io, Path::A, RF_CHNLBW, next)?;
    *chnlval = next;
    Ok(())
}

/// RF leg of `_rtl8723e_phy_sw_chnl_step_by_step`, after the caller has
/// programmed the channel's calibrated TX power. UMC-B keeps the source's
/// read-and-write-back branch outside channel 6 at 20 MHz.
pub async fn sw_chnl_rf(
    io: &impl Io,
    version: Version,
    chnlval: &mut u32,
    channel: u8,
    forty: bool,
) -> Result<(), Error> {
    if !(1..=14).contains(&channel) {
        return Err(Error::State);
    }
    let next = (*chnlval & 0xffff_fc00) | u32::from(channel);
    rf_serial_write(io, Path::A, RF_CHNLBW, next)?;
    if version.is_umc_b_cut() {
        let value = if channel == 6 && !forty {
            0x00255
        } else {
            get_rf(io, Path::A, RF_RX_G1, RFREG_OFFSET_MASK).await?
        };
        set_rf(io, Path::A, RF_RX_G1, MASKDWORD, value).await?;
    }
    io.delay_us(10_000).await;
    *chnlval = next;
    Ok(())
}

/// `rtl8723e_phy_set_rfpath_switch(main, false)` during cold init, while
/// `is_hal_stop` is still true. It is separate from IQK and TX admission.
pub fn rfpath_switch_main(io: &impl Io) -> Result<(), Error> {
    set_bb(io, 0x004c, 1 << 23, 1)?;
    set_bb(io, 0x0878, 1 << 13, 1)?;
    set_bb(io, 0x0860, 0x300, 2)
}

/// `_rtl8723e_phy_lc_calibrate(is2t = false)` with the source's unmasked
/// 12-bit RF RMW behavior (data bit 15/16 is intentionally not masked).
pub async fn lc_calibrate(io: &impl Io) -> Result<(), Error> {
    let old = io.read8(0x0d03)?;
    let continuous = old & 0x70 != 0;
    if continuous {
        io.write8(0x0d03, old & 0x8f)?;
    } else {
        io.write8(0x0522, 0xff)?;
    }
    let mut mode = 0;
    if continuous {
        mode = get_rf(io, Path::A, 0, 0xfff).await?;
        set_rf(io, Path::A, 0, 0xfff, (mode & 0x8ffff) | 0x10000).await?;
    }
    let lc = get_rf(io, Path::A, 0x18, 0xfff).await?;
    set_rf(io, Path::A, 0x18, 0xfff, lc | 0x08000).await?;
    io.delay_us(100_000).await;
    if continuous {
        io.write8(0x0d03, old)?;
        set_rf(io, Path::A, 0, 0xfff, mode).await?;
    } else {
        io.write8(0x0522, 0)?;
    }
    Ok(())
}
