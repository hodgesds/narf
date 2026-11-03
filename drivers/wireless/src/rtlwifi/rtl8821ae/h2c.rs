// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE host-to-firmware commands, LPS RPWM and the PCI interrupt
//! profile.
//!
//! Exact `rtl8821ae/fw.c`: `_rtl8821ae_fill_h2c_command` (byte-wise box
//! writes; 4–7-byte commands write the zero-padded four-byte extension box
//! first), `_rtl8821ae_check_fw_read_last_h2c`,
//! `rtl8821ae_set_fw_media_status_rpt_cmd`, `rtl8821ae_set_fw_pwrmode_cmd`,
//! `rtl8821ae_set_fw_rsvdpagepkt`'s location command; `rtl8821ae/hw.c`:
//! `rtl8821ae_update_hal_rate_mask` (2.4 GHz B/G/N 1T1R station, 20 MHz
//! channel), `HW_VAR_SET_RPWM`, `_rtl8821ae_fwlps_{enter,leave}`
//! (`low_power_enable` false), `rtl8821ae_{enable,disable}_interrupt` with
//! `int_clear`, `rtl8821ae_clear_interrupt` and
//! `rtl8821ae_interrupt_recognized`; `rtl8821ae/sw.c` masks.
//!
//! BT coexistence: Linux 8821AE always reports `get_btc_status() == true`,
//! but `btc_is_bt_ctrl_lps` stays false until a coex algorithm takes LPS
//! control, which only happens on boards with BT (`REG_MULTI_FUNC_CTRL[18]`,
//! `_rtl8821ae_read_bt_coexist_info_from_hwpg`). Coexistence is not
//! implemented; the commands here are the `bt_ctrl_lps == false` forms and a
//! board with the BT function is not admitted by the owner.
//!
//! Differences from Linux: a full HMETFR wait or a `REG_CR == 0xEA`
//! (powered-off MAC) box is reported as an error instead of silently
//! dropping the command, and the mailbox is then poisoned.

use crate::rtlwifi::firmware_transport::{Error as AccessError, Io};
use crate::rtlwifi::prepare::Error;

pub const REG_CR: u16 = 0x0100;
pub const REG_SYS_CFG1: u16 = 0x00fc;
pub const REG_TXDMA_STATUS: u16 = 0x0210;
pub const REG_TXPKT_EMPTY: u16 = 0x041a;
pub const REG_HMETFR: u16 = 0x01cc;
pub const REG_HMEBOX_0: u16 = 0x01d0;
pub const REG_HMEBOX_EXT_0: u16 = 0x01f0;
pub const REG_PCIE_HRPWM: u16 = 0x0361;
pub const REG_BCN_CTRL: u16 = 0x0550;

/// `enum rtl8821a_h2c_cmd` ids used by the station owner.
pub const H2C_RSVDPAGE: u8 = 0x00;
pub const H2C_MSRRPT: u8 = 0x01;
pub const H2C_SETPWRMODE: u8 = 0x20;
pub const H2C_RA_MASK: u8 = 0x40;

/// `FW_PS_ACK` / `FW_PS_TOGGLE`; `FW_PS_STATE_{ALL_ON,RF_OFF}_8821AE` are
/// both `FW_PS_CLOCK_ON` (0).
pub const FW_PS_TOGGLE: u8 = 1 << 7;
pub const FW_PS_STATE_ALL_ON: u8 = 0;
pub const FW_PS_STATE_RF_OFF: u8 = 0;
/// `FW_PWR_STATE_ACTIVE` = `FW_PS_RF_ON | FW_PS_REGISTER_ACTIVE`.
pub const FW_PWR_STATE_ACTIVE: u8 = (1 << 2) | (1 << 3);
pub const FW_PWR_STATE_RF_OFF: u8 = 0;

/// HMETFR wait: one check plus 99 × 10 us retries (`wait_h2c_limmit`).
const HMETFR_CHECKS: u32 = 100;

/// `rtlhal->last_hmeboxnum` plus a poison bit set by a failed command.
#[derive(Debug, Default)]
pub struct Mailbox {
    next: u8,
    pub failed: bool,
}

impl Mailbox {
    pub fn next_box(&self) -> u8 {
        self.next
    }

    /// `rtl8821ae_fill_h2c_cmd` → `_rtl8821ae_fill_h2c_command`.
    pub async fn fill(&mut self, io: &impl Io, id: u8, payload: &[u8]) -> Result<(), Error> {
        if self.failed || payload.is_empty() || payload.len() > 7 {
            return Err(Error::State);
        }
        self.failed = true;
        let boxnum = self.next;
        if io.read8(REG_CR)? == 0xea {
            if io.read8(REG_TXDMA_STATUS)? == 0xea || io.read8(REG_TXPKT_EMPTY)? == 0xea {
                io.write8(REG_SYS_CFG1 + 3, 0xff)?;
            }
            return Err(Error::RadioOff);
        }
        let mut read = false;
        for check in 0..HMETFR_CHECKS {
            if check != 0 {
                io.delay_us(10).await;
            }
            let hmetfr = io.read8(REG_HMETFR)?;
            if hmetfr == 0xff {
                return Err(Error::Access(AccessError::Gone));
            }
            if (hmetfr >> boxnum) & 1 == 0 {
                read = true;
                break;
            }
        }
        if !read {
            return Err(Error::CommandTimeout);
        }
        let mut content = [0u8; 4];
        content[0] = id;
        let base = REG_HMEBOX_0 + u16::from(boxnum) * 4;
        if payload.len() > 3 {
            let mut ext = [0u8; 4];
            ext[..payload.len() - 3].copy_from_slice(&payload[3..]);
            let ext_base = REG_HMEBOX_EXT_0 + u16::from(boxnum) * 4;
            for (i, b) in ext.iter().enumerate() {
                io.write8(ext_base + i as u16, *b)?;
            }
            content[1..4].copy_from_slice(&payload[..3]);
        } else {
            content[1..1 + payload.len()].copy_from_slice(payload);
        }
        for (i, b) in content.iter().enumerate() {
            io.write8(base + i as u16, *b)?;
        }
        self.next = (boxnum + 1) & 3;
        self.failed = false;
        Ok(())
    }
}

/// `rtl8821ae_set_fw_media_status_rpt_cmd` payload (INFRA station, MACID 0).
pub fn media_status(connected: bool) -> [u8; 3] {
    [u8::from(connected), 0, 0]
}

/// `fwctrl_psmode` values used by this owner (`wifi.h` `FW_PS_*_MODE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PsMode {
    /// `FW_PS_ACTIVE_MODE` (0).
    Active,
    /// `FW_PS_MAX_MODE` (2): `sw.c` sets `reg_fwctrl_lps = 2`.
    Max,
}

/// `rtl8821ae_set_fw_pwrmode_cmd` payload for a non-P2P station without BT
/// LPS control.
pub fn pwrmode(mode: PsMode) -> [u8; 7] {
    let (mode_byte, rlbm, awake, state) = match mode {
        // FW_PS_ACTIVE_MODE falls to the switch default (rlbm 2, interval 4).
        PsMode::Active => (0, 2, 4, FW_PWR_STATE_ACTIVE),
        PsMode::Max => (1, 1, 2, FW_PWR_STATE_RF_OFF),
    };
    // SMART_PS = 1 (bt_ctrl_lps false, not P2P); ALL_QUEUE_UAPSD 0; byte5 0x40.
    [mode_byte, rlbm | (1 << 4), awake, 0, state, 0x40, 0]
}

/// `rtl8821ae_set_fw_rsvdpagepkt` location command (`H2C_8821AE_RSVDPAGE`,
/// 5 bytes): PS-Poll, Null, QoS-Null and BT-QoS-Null page indices.
pub fn rsvdpage_location(pspoll: u8, null: u8, qos_null: u8, bt_qos_null: u8) -> [u8; 5] {
    [0, pspoll, null, qos_null, bt_qos_null]
}

/// `HW_VAR_SET_RPWM`: the requested state goes out with BIT(7) chosen
/// against the current HRPWM toggle exactly as Linux writes it.
pub async fn set_rpwm(io: &impl Io, value: u8) -> Result<(), Error> {
    let current = io.read8(REG_PCIE_HRPWM)?;
    io.delay_us(1).await;
    let out = if current & FW_PS_TOGGLE != 0 {
        value
    } else {
        value | FW_PS_TOGGLE
    };
    io.write8(REG_PCIE_HRPWM, out)?;
    Ok(())
}

/// `_rtl8821ae_fwlps_leave` (`low_power_enable` false): RPWM all-on, then
/// `SETPWRMODE(ACTIVE)`.
pub async fn fwlps_leave(io: &impl Io, mailbox: &mut Mailbox) -> Result<(), Error> {
    set_rpwm(io, FW_PS_STATE_ALL_ON).await?;
    mailbox
        .fill(io, H2C_SETPWRMODE, &pwrmode(PsMode::Active))
        .await
}

/// `_rtl8821ae_fwlps_enter` (`low_power_enable` false): `SETPWRMODE(MAX)`,
/// then RPWM RF-off.
pub async fn fwlps_enter(io: &impl Io, mailbox: &mut Mailbox) -> Result<(), Error> {
    mailbox
        .fill(io, H2C_SETPWRMODE, &pwrmode(PsMode::Max))
        .await?;
    set_rpwm(io, FW_PS_STATE_RF_OFF).await
}

/// `sta_entry->wireless_mode` for a 2.4 GHz station (`core.c::rtl_op_sta_add`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WirelessMode {
    B,
    G,
    N24,
}

/// Peer facts `rtl8821ae_update_hal_rate_mask` reads from `ieee80211_sta`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    /// `supp_rates[NL80211_BAND_2GHZ]`: bits 0–3 CCK 1/2/5.5/11, 4–11 OFDM.
    pub legacy: u16,
    /// `ht_cap.ht_supported` with `mcs.rx_mask[0]`, `[1]`.
    pub ht: Option<[u8; 2]>,
    pub sgi20: bool,
    pub sgi40: bool,
}

impl Peer {
    pub fn mode(&self) -> WirelessMode {
        if self.ht.is_some() {
            WirelessMode::N24
        } else if self.legacy <= 0xf {
            WirelessMode::B
        } else {
            WirelessMode::G
        }
    }
}

/// `rtl8821ae_update_hal_rate_mask` H2C payload for the INFRA station (MACID
/// 0, `rf_type` 1T1R, `current_chan_bw` 20 MHz). `bw40` is `mac->bw_40`;
/// `rssi_level` is the DM level (0 at association). Returns the 7-byte
/// `H2C_8821AE_RA_MASK` body; the caller then sets `REG_BCN_CTRL` BIT(3).
pub fn rate_mask(peer: &Peer, bw40: bool, rssi_level: u8, update_bw: bool) -> [u8; 7] {
    let mode = peer.mode();
    let mut bitmap = u32::from(peer.legacy);
    if let Some(rx) = peer.ht {
        bitmap |= (u32::from(rx[1]) << 20) | (u32::from(rx[0]) << 12);
    }
    // rtl_mrate_idx_to_arfr_id(ratr_index) for a 1T1R PHY.
    let arfr_id: u8 = match mode {
        WirelessMode::B => {
            bitmap &= if bitmap & 0xc != 0 { 0xd } else { 0xf };
            8 // RATR_INX_WIRELESS_B → RATEID_IDX_B
        }
        WirelessMode::G => {
            bitmap &= match rssi_level {
                1 => 0x0000_0f00,
                2 => 0x0000_0ff0,
                _ => 0x0000_0ff5,
            };
            6 // RATR_INX_WIRELESS_GB → RATEID_IDX_BG
        }
        WirelessMode::N24 => {
            // mimo_ps is IEEE80211_SMPS_OFF; rf_type 1T1R.
            bitmap &= match (rssi_level, bw40) {
                (1, _) => 0x000f_0000,
                (2, _) => 0x000f_f000,
                (_, true) => 0x000f_f015,
                (_, false) => 0x000f_f005,
            };
            1 // RATR_INX_WIRELESS_NGB → RATEID_IDX_BGN_40M_1SS
        }
    };
    let sgi = peer.ht.is_some() && (peer.sgi20 || peer.sgi40);
    // current_chan_bw 0 | !update_bw << 3 | vht_eni 0 | ldpc 0.
    let byte2 = u8::from(!update_bw) << 3;
    let b = bitmap.to_le_bytes();
    [
        0,
        arfr_id | if sgi { 0x80 } else { 0 },
        byte2,
        b[0],
        b[1],
        b[2],
        b[3],
    ]
}

/// `_rtl8821ae_set_bcn_ctrl_reg` against the cached `reg_bcn_ctrl_val`.
pub fn set_bcn_ctrl(io: &impl Io, cached: &mut u8, set: u8, clear: u8) -> Result<(), Error> {
    *cached |= set;
    *cached &= !clear;
    io.write8(REG_BCN_CTRL, *cached)?;
    Ok(())
}

// ── PCI interrupt profile (`sw.c` masks, `hw.c` enable/disable/recognize) ──

pub const REG_HSIMR: u16 = 0x0058;
pub const REG_HSISR: u16 = 0x005c;
pub const REG_HIMR: u16 = 0x00b0;
pub const REG_HISR: u16 = 0x00b4;
pub const REG_HIMRE: u16 = 0x00b8;
pub const REG_HISRE: u16 = 0x00bc;

/// `rtlpci->irq_mask[0]`, `[1]` and `sys_irq_mask` (`sw.c`, kept in `mac`).
pub const IRQ_MASK0: u32 = super::mac::IRQ_MASK[0];
pub const IRQ_MASK1: u32 = super::mac::IRQ_MASK[1];
pub const SYS_IRQ_MASK: u32 = super::mac::SYS_IRQ_MASK;

/// `rtl8821ae_clear_interrupt`: write back HISR, HISRE, HSISR.
pub fn clear_interrupt(io: &impl Io) -> Result<(), Error> {
    for reg in [REG_HISR, REG_HISRE, REG_HSISR] {
        let pending = io.read32(reg)?;
        if pending == u32::MAX {
            return Err(Error::Access(AccessError::Gone));
        }
        io.write32(reg, pending)?;
    }
    Ok(())
}

/// `rtl8821ae_enable_interrupt` with `int_clear` (module default true).
/// Linux leaves `REG_C2HEVT_CLEAR` alone on this chip.
pub fn enable_interrupt(io: &impl Io) -> Result<(), Error> {
    clear_interrupt(io)?;
    io.write32(REG_HIMR, IRQ_MASK0)?;
    io.write32(REG_HIMRE, IRQ_MASK1)?;
    io.write32(REG_HSIMR, SYS_IRQ_MASK)?;
    Ok(())
}

/// `rtl8821ae_disable_interrupt` (`IMR_DISABLED`).
pub fn disable_interrupt(io: &impl Io) -> Result<(), Error> {
    io.write32(REG_HIMR, 0)?;
    io.write32(REG_HIMRE, 0)?;
    Ok(())
}

/// One `pci.c::_rtl_pci_interrupt` recognition pass for this chip: disable,
/// `rtl8821ae_interrupt_recognized` (W1C under the masks), then enable —
/// which, with `int_clear`, also clears anything that arrived meanwhile, as
/// in Linux. `_rtl_pci_hs_interrupt` is 88EE/8723BE-only and is not run.
/// Ring service follows in the caller where Linux runs the RX/TX handlers
/// (between recognition and enable; the clear on enable only drops status
/// bits, never descriptor ownership). Returns `(inta, intb)`.
pub fn service_interrupt(io: &impl Io) -> Result<(u32, u32), Error> {
    disable_interrupt(io)?;
    let raw = io.read32(REG_HISR)?;
    if raw == u32::MAX {
        return Err(Error::Access(AccessError::Gone));
    }
    let inta = raw & IRQ_MASK0;
    io.write32(REG_HISR, inta)?;
    let intb = io.read32(REG_HISRE)? & IRQ_MASK1;
    io.write32(REG_HISRE, intb)?;
    enable_interrupt(io)?;
    Ok((inta, intb))
}
