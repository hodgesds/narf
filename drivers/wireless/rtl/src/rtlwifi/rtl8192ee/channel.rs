// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE 2.4 GHz channel switch and 20/40 MHz bandwidth.
//!
//! Exact register effects in the `core.c::rtl_op_config` order
//! (`current_chan_bw` and `cur_40_prime_sc` set, the wide channel stored —
//! HT40+ primary + 2 with `PRIME_CHNL_OFFSET_LOWER`, HT40- primary - 2 with
//! `PRIME_CHNL_OFFSET_UPPER` — then `switch_channel`, then `set_bw_mode`):
//!
//! - `rtl92ee_phy_sw_chnl` → `_rtl92ee_phy_sw_chnl_step_by_step`:
//!   `rtl92ee_phy_set_txpower_level(channel)` at the new width, then for
//!   both paths `rfreg_chnlval[p] = (rfreg_chnlval[p] & 0xfffff00) |
//!   channel` written through `rtl_set_rfreg(RF_CHNLBW, 0x3ff, ..)` (Linux
//!   does not mask the value to the field), then the command's 10 ms delay.
//!   The callback leaves the step machine there (post-common is empty).
//! - `rtl92ee_phy_set_bw_mode_callback`: `REG_BWOPMODE` BIT(2), at 40 MHz
//!   `REG_RRSR + 2 = (v & 0x90) | (sc << 5)`; `RFPGA0/1_RFMOD` BRFMOD, at
//!   20 MHz `ROFDM0_TXPSEUDONOISEWGT[31:30] = 0`, at 40 MHz
//!   `RCCK0_SYSTEM` sideband `sc >> 1`, `ROFDM1_LSTF[11:10] = sc`, `0x818[27:26]
//!   = (sc == LOWER) ? 2 : 1`; then `rtl92ee_phy_rf6052_set_bandwidth`
//!   (`rfreg_chnlval[0]` bits 10/11 written to both paths, as Linux).
//!
//! `set_channel_access` (slot/SIFS) between the two is the MAC owner's.

use super::phy::ByRate;
use super::phy::{set_bb, set_rf, Path, PATHS, RFPGA0_RFMOD, RFREG_OFFSET_MASK, RF_CHNLBW};
use super::txpower::{self, Efuse, Width};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const REG_RRSR: u16 = 0x0440;
pub const REG_BWOPMODE: u16 = 0x0603;
pub const BW_OPMODE_20MHZ: u8 = 1 << 2;
pub const RFPGA1_RFMOD: u16 = 0x0900;
pub const RCCK0_SYSTEM: u16 = 0x0a00;
pub const ROFDM0_TXPSEUDONOISEWGT: u16 = 0x0ce4;
pub const ROFDM1_LSTF: u16 = 0x0d00;
pub const BRFMOD: u32 = 0x1;
pub const BCCK_SIDEBAND: u32 = 0x10;

/// `HAL_PRIME_CHNL_OFFSET_*` (`rtl8192ee/def.h`).
pub const PRIME_DONT_CARE: u8 = 0;
pub const PRIME_LOWER: u8 = 1;
pub const PRIME_UPPER: u8 = 2;

/// `nl80211_channel_type` on 2.4 GHz.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelType {
    Ht20,
    Ht40Plus,
    Ht40Minus,
}

/// The `rtl_op_config` channel state for one primary channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Operating {
    pub primary: u8,
    pub wide: u8,
    pub width: Width,
    pub prime_sc: u8,
}

impl Operating {
    /// 2.4 GHz channels 1..=14 only; HT40 must keep the wide channel and
    /// both 20 MHz halves inside 1..=13 (Linux clamps `wide_chan <= 0` to 1,
    /// which never lands a valid 40 MHz pair; such requests are refused).
    pub fn new(primary: u8, kind: ChannelType) -> Result<Self, Error> {
        if !(1..=14).contains(&primary) {
            return Err(Error::State);
        }
        let (wide, width, prime_sc) = match kind {
            ChannelType::Ht20 => (primary, Width::W20, PRIME_DONT_CARE),
            ChannelType::Ht40Plus => (primary + 2, Width::W40, PRIME_LOWER),
            ChannelType::Ht40Minus => (primary.wrapping_sub(2), Width::W40, PRIME_UPPER),
        };
        if width == Width::W40 && !(3..=11).contains(&wide) {
            return Err(Error::State);
        }
        Ok(Self {
            primary,
            wide,
            width,
            prime_sc,
        })
    }
}

/// `_rtl92ee_phy_sw_chnl_step_by_step` as run by `rtl92ee_phy_sw_chnl`.
pub async fn sw_chnl(
    io: &impl Io,
    efuse: &Efuse,
    by_rate: &ByRate,
    width: Width,
    channel: u8,
    chnlval: &mut [u32; 2],
) -> Result<(), Error> {
    txpower::set_level(io, efuse, by_rate, width, channel)?;
    for path in PATHS {
        let p = path as usize;
        chnlval[p] = (chnlval[p] & 0x0fff_ff00) | u32::from(channel);
        set_rf(io, path, RF_CHNLBW, 0x3ff, chnlval[p]).await?;
    }
    io.delay_us(10_000).await;
    Ok(())
}

/// `rtl92ee_phy_rf6052_set_bandwidth`.
pub async fn rf_set_bandwidth(
    io: &impl Io,
    width: Width,
    chnlval: &mut [u32; 2],
) -> Result<(), Error> {
    chnlval[0] = match width {
        Width::W20 => (chnlval[0] & 0xffff_f3ff) | (1 << 10) | (1 << 11),
        Width::W40 => (chnlval[0] & 0xffff_f3ff) | (1 << 10),
    };
    set_rf(io, Path::A, RF_CHNLBW, RFREG_OFFSET_MASK, chnlval[0]).await?;
    set_rf(io, Path::B, RF_CHNLBW, RFREG_OFFSET_MASK, chnlval[0]).await
}

/// `rtl92ee_phy_set_bw_mode_callback`.
pub async fn set_bw_mode(
    io: &impl Io,
    width: Width,
    prime_sc: u8,
    chnlval: &mut [u32; 2],
) -> Result<(), Error> {
    let opmode = io.read8(REG_BWOPMODE)?;
    let rrsr = io.read8(REG_RRSR + 2)?;
    match width {
        Width::W20 => io.write8(REG_BWOPMODE, opmode | BW_OPMODE_20MHZ)?,
        Width::W40 => {
            io.write8(REG_BWOPMODE, opmode & !BW_OPMODE_20MHZ)?;
            io.write8(REG_RRSR + 2, (rrsr & 0x90) | (prime_sc << 5))?;
        }
    }
    match width {
        Width::W20 => {
            set_bb(io, RFPGA0_RFMOD, BRFMOD, 0)?;
            set_bb(io, RFPGA1_RFMOD, BRFMOD, 0)?;
            set_bb(io, ROFDM0_TXPSEUDONOISEWGT, (1 << 31) | (1 << 30), 0)?;
        }
        Width::W40 => {
            let sc = u32::from(prime_sc);
            set_bb(io, RFPGA0_RFMOD, BRFMOD, 1)?;
            set_bb(io, RFPGA1_RFMOD, BRFMOD, 1)?;
            set_bb(io, RCCK0_SYSTEM, BCCK_SIDEBAND, sc >> 1)?;
            set_bb(io, ROFDM1_LSTF, 0xc00, sc)?;
            set_bb(
                io,
                0x818,
                (1 << 26) | (1 << 27),
                if prime_sc == PRIME_LOWER { 2 } else { 1 },
            )?;
        }
    }
    rf_set_bandwidth(io, width, chnlval).await
}

/// `_rtl92ee_phy_sw_chnl_step_by_step` with the envelope-admitted TXAGC
/// indices ([`txpower::set_indices`]) in place of the Linux index.
pub async fn sw_chnl_admitted(
    io: &impl Io,
    indices: &[[u8; 28]; 2],
    channel: u8,
    chnlval: &mut [u32; 2],
) -> Result<(), Error> {
    txpower::set_indices(io, indices)?;
    for path in PATHS {
        let p = path as usize;
        chnlval[p] = (chnlval[p] & 0x0fff_ff00) | u32::from(channel);
        set_rf(io, path, RF_CHNLBW, 0x3ff, chnlval[p]).await?;
    }
    io.delay_us(10_000).await;
    Ok(())
}

/// [`configure`] for an admitted envelope operating point: the switch at
/// the wide channel with the permission's indices, then `set_bw_mode`.
pub async fn configure_admitted(
    io: &impl Io,
    permission: &super::envelope::Permission,
    chnlval: &mut [u32; 2],
) -> Result<(), Error> {
    let op = permission.operating().channel().ok_or(Error::State)?;
    sw_chnl_admitted(io, permission.indices(), op.wide, chnlval).await?;
    set_bw_mode(io, op.width, op.prime_sc, chnlval).await
}

/// `switch_channel` then `set_bw_mode` at the wide channel.
pub async fn configure(
    io: &impl Io,
    efuse: &Efuse,
    by_rate: &ByRate,
    op: &Operating,
    chnlval: &mut [u32; 2],
) -> Result<(), Error> {
    sw_chnl(io, efuse, by_rate, op.width, op.wide, chnlval).await?;
    set_bw_mode(io, op.width, op.prime_sc, chnlval).await
}
