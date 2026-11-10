// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE hardware init (`rtl92de_hw_init`, `rtl8192de/hw.c`).
//!
//! The post-download tail of `rtl92de_hw_init`, from the `0x605`
//! write through the RF-ready poll. Linux's head —
//! `rtl92d_phy_reset_iqk_result` (software-only, no state to reset
//! here), `_rtl92de_init_mac` (the power-on prefix + LLT + MAC init
//! + ring DESA bases) and `rtl92d_download_fw` — runs elsewhere in
//! NARF: the firmware download is `firmware_transport::run_8192de`
//! (step 2), the LLT + ring bases are `Prepared::prepare` (this
//! lane), and the power-on prefix + MAC init are the first two steps
//! here ([`power::power_on`], [`mac::init_mac`]).
//!
//! Order deviation from Linux, and why it is safe: Linux powers on
//! (CR `0x2ff`, PCIe DMA-stop cleared) *before* the LLT, rings and
//! firmware download; NARF runs LLT + rings + download first, then
//! this configure step powers on. The host DMA gates stay closed
//! throughout — the PCIe bus-master enable is a packet-start concern
//! owned by the future `Prepared::Chip::Rtl8192de` packet path — so
//! opening the on-chip CR gates in this step cannot move host DMA.
//! `power_on`'s own dual-MAC wait (the other function finishing its
//! power-off) is preserved by running it here.
//!
//! Steps, in Linux order:
//!
//! 1. `power::power_on` + `mac::init_mac` (the `_rtl92de_init_mac`
//!    power prefix and MAC init, minus the LLT + ring bases that
//!    `Prepared::prepare` already programmed).
//! 2. `0x605 |= 0x30` (`REG_TCR` byte 1; a no-op under the
//!    `0x3200` TCR `init_mac` wrote, applied anyway as Linux does).
//! 3. Early mode: not implemented in NARF (no early-mode support
//!    anywhere in-tree); the `0x4d0 |= 0x1f`, `0x4d3 = 0x80`,
//!    `0x605 |= 0x40` writes are skipped.
//! 4. RDG: skipped — `mac->rdg_en` is never assigned upstream, so
//!    the `REG_RD_CTRL` / `REG_RD_NAV_NXT` / `REG_RD_RESP_PKT_TH`
//!    writes never execute in Linux either.
//! 5. `phy::mac_config`, then `mac::trim_receive_config` (the RCR
//!    read-back with `RCR_ACRC32 | RCR_AICV` cleared).
//! 6. `phy::bb_config`, `RFPGA0_ANALOGPARAMETER4` `0x00f00000 ← 0xf`,
//!    `phy::rf_config`, `channel::update_bbrf_configuration`,
//!    `RFPGA0_ANALOGPARAMETER4` `0x00f00000 ← 0`, then the
//!    `rfreg_chnlval` reads (`RF_CHNLBW` on both paths, also on a
//!    1T part, as Linux does).
//! 7. CCK block on (2.4 GHz only) + OFDM block on, then
//!    `RFPGA0_ANALOGPARAMETER2` bits 10|11 `← 3` (both interface
//!    indices take the same value in Linux).
//! 8. `mac::hw_configure`, `mac::cam_reset`, and the software-crypto
//!    station identity (`mac::station_identity`: `REG_SECCFG` 0 +
//!    MAC address into `REG_MACID`). Enabling hardware security
//!    (`rtl92de_enable_hw_security_config`: `REG_CR+1 = 0x02` plus
//!    the `SCR_*` `REG_SECCFG` value) is a follow-up keyed on the
//!    `sw_crypto` decision; the in-tree station code is
//!    software-crypto.
//! 9. `phy::original_values` + `txpower::set_level` at the current
//!    channel. The ASPM back-door (`_rtl92de_enable_aspm_back_door`)
//!    is skipped with a note — ASPM stays disabled, as in the 92CE
//!    port — and `rtl92d_dm_init` is software-only (no DM owner yet).
//! 10. LC calibrate (`rtl92d_phy_lc_calibrate`) is a follow-up lane
//!     (mechanical RF calibration, ~100 lines); `rtl92d_phy_reset_iqk_result`
//!     is software-only. Then, on a dual-MAC-dual-PHY part, the
//!     RF-ready poll: `RF_SYN_G6` (`0x2a`) BIT(11) on path A, up to
//!     10,000 × 50 µs (`MAX_STALL_TIME`); expiry refuses with
//!     [`Error::PacketTimeout`] and leaves the radio off.
//!
//! The result is a [`Radio`]: the configured mode, band, RF type,
//! channel values, receive config, initial gains, frame sync, TX
//! power levels, the factory power-group store (absent when autoload
//! failed), and `rf_on` (ERFON at the end of a successful init).
//! The mailbox starts at box 0 (`last_hmeboxnum = 0`) and
//! `fw_current_inpsmode` starts false, as Linux sets them before
//! the tail; both live with the station owner, not here.

use super::calib::IqkMatrix;
use super::channel::{self, Bbrf};
use super::phy::{self, OriginalValues, PgStore};
use super::txpower::{self, Efuse, PowerLevels};
use super::{mac, power, Band, MacPhyMode, RfType};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// `REG_TCR` byte 1 (`rtl8192de/hw.c` `0x605` write).
pub const REG_TCR_BYTE1: u16 = 0x0605;
/// `RF_SYN_G6` (`rtl8192d/reg.h`): the RF-ready poll register.
pub const RF_SYN_G6: u32 = 0x2a;
/// `RF_SYN_G6` LO-ready bit.
pub const RF_SYN_G6_READY: u32 = 1 << 11;
/// `MAX_STALL_TIME` (µs) per RF-ready poll iteration.
pub const RF_READY_POLL_US: u64 = 50;
/// RF-ready poll iterations (`rtl92de_hw_init`).
pub const RF_READY_POLLS: usize = 10_000;

/// The `rtl92de_hw_init` inputs: device config, the operating
/// point, and the factory data the tail needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// MAC/PHY mode (from the PROM read).
    pub mode: MacPhyMode,
    /// Function index (0 = MAC0, 1 = MAC1).
    pub interface_index: u8,
    /// Operating band.
    pub band: Band,
    /// Station MAC address (into `REG_MACID`).
    pub mac: [u8; 6],
    /// Factory TX-power data (from the EFUSE logical map).
    pub efuse: Efuse,
    /// RF type (from the PROM read).
    pub rf_type: RfType,
    /// Current channel (for the TX-power level).
    pub channel: u8,
    /// 40 MHz width at the operating point.
    pub bw40: bool,
    /// EFUSE autoload failed (PG walk skipped, TX power from
    /// defaults).
    pub autoload_fail: bool,
}

/// The `rtl92de_hw_init` report (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Radio {
    /// Configured MAC/PHY mode.
    pub mode: MacPhyMode,
    /// Function index.
    pub interface_index: u8,
    /// Operating band.
    pub band: Band,
    /// RF type.
    pub rf_type: RfType,
    /// `rtlphy->rfreg_chnlval` (both paths).
    pub chnlval: [u32; 2],
    /// `rtlphy->iqk_matrix` (stored IQK calibration, reloaded on
    /// channel switch; reset by `rtl92de_hw_init` before any switch).
    pub iqk: IqkMatrix,
    /// Trimmed receive config (`RCR & ~(RCR_ACRC32 | RCR_AICV)`).
    pub receive_config: u32,
    /// Whether the CCK path runs at high power.
    pub cck_high_power: bool,
    /// Default initial gains (from [`OriginalValues`]).
    pub initialgain: [u8; 4],
    /// Frame-sync byte (from [`OriginalValues`]).
    pub framesync: u8,
    /// Frame-sync C34 dword (from [`OriginalValues`]).
    pub framesync_c34: u32,
    /// TX power levels at the current channel.
    pub power_levels: PowerLevels,
    /// Factory power-group store (absent when autoload failed).
    pub pg: Option<PgStore>,
    /// `ppsc->rfpwr_state == ERFON` (always true on success).
    pub rf_on: bool,
}

/// The `rtl92de_hw_init` post-download tail (see the module docs
/// for the step order and the deviations).
pub async fn configure(io: &impl Io, params: &Params) -> Result<Radio, Error> {
    let band_5g = params.band == Band::On5Ghz;
    power::power_on(io, params.mode, params.interface_index, params.band).await?;
    mac::init_mac(io, params.mode).await?;
    let tcr = io.read8(REG_TCR_BYTE1)?;
    io.write8(REG_TCR_BYTE1, tcr | 0x30)?;
    phy::mac_config(io, params.mode)?;
    let receive_config = mac::trim_receive_config(io)?;
    let bb = phy::bb_config(
        io,
        params.rf_type,
        params.interface_index,
        band_5g,
        params.autoload_fail,
    )
    .await?;
    phy::set_bb(io, phy::RFPGA0_ANALOGPARAMETER4, 0x00f0_0000, 0xf)?;
    phy::rf_config(
        io,
        params.mode,
        params.interface_index,
        band_5g,
        params.rf_type,
        params.efuse.internal_pa_5g,
    )
    .await?;
    let mut chnlval = [0u32; 2];
    let bbrf = Bbrf {
        mode: params.mode,
        rf_type: params.rf_type,
        interface_index: params.interface_index,
        eeprom_c9: params.efuse.eeprom_c9,
        eeprom_cc: params.efuse.eeprom_cc,
        internal_pa_5g: params.efuse.internal_pa_5g,
    };
    channel::update_bbrf_configuration(io, params.band, &bbrf, &mut chnlval).await?;
    phy::set_bb(io, phy::RFPGA0_ANALOGPARAMETER4, 0x00f0_0000, 0)?;
    chnlval[0] = phy::get_rf(io, phy::Path::A, phy::RF_CHNLBW, phy::RFREG_OFFSET_MASK).await?;
    chnlval[1] = phy::get_rf(io, phy::Path::B, phy::RF_CHNLBW, phy::RFREG_OFFSET_MASK).await?;
    if !band_5g {
        phy::set_bb(io, phy::RFPGA0_RFMOD, phy::BCCKEN, 0x1)?;
    }
    phy::set_bb(io, phy::RFPGA0_RFMOD, phy::BOFDMEN, 0x1)?;
    phy::set_bb(io, phy::RFPGA0_ANALOGPARAMETER2, (1 << 10) | (1 << 11), 3)?;
    mac::hw_configure(io, params.mode)?;
    mac::cam_reset(io)?;
    mac::station_identity(io, &params.mac)?;
    let OriginalValues {
        initialgain,
        framesync,
        framesync_c34,
    } = phy::original_values(io)?;
    // `set_level` early-returns the no-EEPROM levels when
    // `txpwr_fromeprom` is clear, which is exactly the autoload-fail
    // case; the factory store is only consulted when it exists.
    let power_levels = match bb.pg {
        Some(pg) => txpower::set_level(
            io,
            &params.efuse,
            params.rf_type,
            &pg,
            params.channel,
            params.band,
            params.bw40,
            false,
        )?,
        None => PowerLevels {
            cck: [0; 2],
            ofdm: [0; 2],
            current: None,
            from_eeprom: false,
        },
    };
    if params.mode == MacPhyMode::DualMacDualPhy {
        let mut ready = false;
        for _ in 0..RF_READY_POLLS {
            io.delay_us(RF_READY_POLL_US).await;
            let reg = phy::get_rf(io, phy::Path::A, RF_SYN_G6, phy::MASKDWORD).await?;
            if reg & RF_SYN_G6_READY == RF_SYN_G6_READY {
                ready = true;
                break;
            }
        }
        if !ready {
            return Err(Error::PacketTimeout);
        }
    }
    Ok(Radio {
        mode: params.mode,
        interface_index: params.interface_index,
        band: params.band,
        rf_type: params.rf_type,
        chnlval,
        iqk: IqkMatrix::new(),
        receive_config,
        cck_high_power: bb.cck_high_power,
        initialgain,
        framesync,
        framesync_c34,
        power_levels,
        pg: bb.pg,
        rf_on: true,
    })
}
