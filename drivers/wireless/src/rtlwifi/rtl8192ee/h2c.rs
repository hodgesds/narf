// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE host-to-firmware commands, LPS RPWM and the PCI interrupt
//! profile.
//!
//! Exact `rtl8192ee/fw.c`: `rtl92ee_fill_h2c_cmd` →
//! `_rtl92ee_fill_h2c_command` (byte-wise box writes; 4–7-byte commands
//! write the zero-padded four-byte extension box first; the `0x130` read
//! after each HMETFR re-check), `_rtl92ee_check_fw_read_last_h2c`,
//! `rtl92ee_set_fw_media_status_rpt_cmd`, `rtl92ee_set_fw_pwrmode_cmd`,
//! `rtl92ee_set_fw_rsvdpagepkt`'s location command; `rtl8192ee/hw.c`:
//! `rtl92ee_update_hal_rate_mask` (2.4 GHz B/G/N **2T2R** station: MCS0-15),
//! `_rtl92ee_mrate_idx_to_arfr_id`, `HW_VAR_SET_RPWM`,
//! `_rtl92ee_fwlps_{enter,leave}` (`low_power_enable` false),
//! `_rtl92ee_set_bcn_ctrl_reg`, `rtl92ee_{enable,disable}_interrupt` and
//! `rtl92ee_interrupt_recognized`; `rtl8192ee/sw.c` masks and LPS module
//! defaults (`reg_fwctrl_lps = 3` ⇒ `FW_PS_DTIM_MODE`,
//! `reg_max_lps_awakeintvl = 5`).
//!
//! Linux power-save gate, kept: `_rtl92ee_fill_h2c_command` returns without
//! touching the hardware while `dot11_psmode != EACTIVE` or
//! `inactive_pwrstate == ERFOFF`. `rtl_lps_set_psmode` sets `dot11_psmode`
//! before `HW_VAR_FW_LPS_ACTION`, so on this chip the LPS-enter
//! `SETPWRMODE` is dropped and only the RPWM RF-off write reaches the
//! hardware, while the LPS-leave `SETPWRMODE(ACTIVE)` is sent. [`Mailbox`]
//! models that gate and reports a dropped command as [`Sent::Dropped`].
//!
//! BT coexistence: the commands are the `bt_ctrl_lps == false` forms. BT
//! boards (`ODM_BOARD_BT`) are refused by the adapter facts, so `btc_ops`
//! never takes LPS control.
//!
//! Differences from Linux: a full HMETFR wait or a `REG_CR == 0xEA`
//! (powered-off MAC) box is reported as an error instead of silently
//! dropping the command, and the mailbox is then poisoned. The Linux
//! `h2c_setinprogress` spin is unnecessary: the owner serialises commands.

use crate::rtlwifi::firmware_transport::{Error as AccessError, Io};
use crate::rtlwifi::prepare::Error;

pub const REG_CR: u16 = 0x0100;
pub const REG_SYS_CFG1: u16 = 0x00f0;
pub const REG_TXDMA_STATUS: u16 = 0x0210;
pub const REG_TXPKT_EMPTY: u16 = 0x041a;
pub const REG_HMETFR: u16 = 0x01cc;
pub const REG_HMEBOX_0: u16 = 0x01d0;
pub const REG_HMEBOX_EXT_0: u16 = 0x01f0;
/// `rtl8192ee/reg.h` `REG_PCIE_HRPWM` (0x3dc; the 88EE/8821AE register is
/// at 0x361).
pub const REG_PCIE_HRPWM: u16 = 0x03dc;
pub const REG_BCN_CTRL: u16 = 0x0550;
/// Read (and discarded) after each HMETFR re-check, as Linux's debug print.
const REG_DEBUG_130: u16 = 0x0130;

/// `enum rtl8192e_h2c_cmd` ids used by the station owner (`fw.h`).
pub const H2C_RSVDPAGE: u8 = 0x00;
pub const H2C_MSRRPT: u8 = 0x01;
pub const H2C_KEEP_ALIVE_CTRL: u8 = 0x03;
pub const H2C_SETPWRMODE: u8 = 0x20;
pub const H2C_RA_MASK: u8 = 0x40;
pub const H2C_RSSI_REPORT: u8 = 0x42;

/// `FW_PS_TOGGLE`; `FW_PS_STATE_{ALL_ON,RF_OFF}_92E` are `FW_PS_CLOCK_ON`.
pub const FW_PS_TOGGLE: u8 = 1 << 7;
pub const FW_PS_STATE_ALL_ON: u8 = 0;
pub const FW_PS_STATE_RF_OFF: u8 = 0;
/// `FW_PWR_STATE_ACTIVE` = `FW_PS_RF_ON | FW_PS_REGISTER_ACTIVE`.
pub const FW_PWR_STATE_ACTIVE: u8 = (1 << 2) | (1 << 3);
pub const FW_PWR_STATE_RF_OFF: u8 = 0;
/// `sw.c`: `reg_max_lps_awakeintvl = 5` (the `FW_PS_DTIM_MODE` interval).
pub const MAX_LPS_AWAKE_INTERVAL: u8 = 5;

/// HMETFR wait: one check plus 99 × 10 us retries (`wait_h2c_limmit`).
const HMETFR_CHECKS: u32 = 100;

/// Outcome of one `rtl92ee_fill_h2c_cmd`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    Written,
    /// Linux's `dot11_psmode != EACTIVE || inactive_pwrstate == ERFOFF`
    /// early return: nothing was written.
    Dropped,
}

/// `rtlhal->last_hmeboxnum`, the Linux power-save gate and a poison bit
/// set by a failed command.
#[derive(Debug)]
pub struct Mailbox {
    next: u8,
    /// `ppsc->dot11_psmode == EACTIVE`.
    pub ps_active: bool,
    /// `ppsc->inactive_pwrstate == ERFOFF` (IPS).
    pub inactive_off: bool,
    pub failed: bool,
}

impl Default for Mailbox {
    fn default() -> Self {
        Self {
            next: 0,
            ps_active: true,
            inactive_off: false,
            failed: false,
        }
    }
}

impl Mailbox {
    pub fn next_box(&self) -> u8 {
        self.next
    }

    /// `rtl92ee_fill_h2c_cmd` → `_rtl92ee_fill_h2c_command`.
    pub async fn fill(&mut self, io: &impl Io, id: u8, payload: &[u8]) -> Result<Sent, Error> {
        if self.failed || payload.is_empty() || payload.len() > 7 {
            return Err(Error::State);
        }
        if !self.ps_active || self.inactive_off {
            return Ok(Sent::Dropped);
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
            if check != 0 {
                io.read8(REG_DEBUG_130)?;
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
        Ok(Sent::Written)
    }
}

/// `rtl92ee_set_fw_media_status_rpt_cmd` payload (INFRA station, MACID 0,
/// `MACID_IND` 0).
pub fn media_status(connected: bool) -> [u8; 3] {
    [u8::from(connected), 0, 0]
}

/// `fwctrl_psmode` values this owner issues (`wifi.h` `FW_PS_*_MODE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PsMode {
    /// `FW_PS_ACTIVE_MODE` (0).
    Active,
    /// `FW_PS_DTIM_MODE` (3): `sw.c` sets `reg_fwctrl_lps = 3`.
    Dtim,
}

/// `rtl92ee_set_fw_pwrmode_cmd` payload for a non-P2P station without BT
/// LPS control (`H2C_92E_PWEMODE_LENGTH` 7).
pub fn pwrmode(mode: PsMode) -> [u8; 7] {
    let (mode_byte, rlbm, awake, state) = match mode {
        // FW_PS_ACTIVE_MODE falls to the switch default (rlbm 2, interval 4).
        PsMode::Active => (0, 2, 4, FW_PWR_STATE_ACTIVE),
        PsMode::Dtim => (1, 2, MAX_LPS_AWAKE_INTERVAL, FW_PWR_STATE_RF_OFF),
    };
    // SMART_PS = 1 (bt_ctrl_lps false, not P2P); ALL_QUEUE_UAPSD 0; byte5 0x40.
    [mode_byte, rlbm | (1 << 4), awake, 0, state, 0x40, 0]
}

/// `rtl92ee_set_fw_rsvdpagepkt` location command (`H2C_92E_RSVDPAGE`,
/// 5 bytes): probe response, PS-Poll, Null, QoS-Null, BT-QoS-Null pages
/// (`PROBERSP_PG` 4, `PSPOLL_PG` 2, `NULL_PG` 3, `QOS_NULL_PG` 6,
/// `BT_QOS_NULL_PG` 7).
pub const RSVDPAGE_LOCATION: [u8; 5] = [4, 2, 3, 6, 7];

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

/// `rtl_lps_set_psmode(EACTIVE)` → `_rtl92ee_fwlps_leave`
/// (`low_power_enable` false): `dot11_psmode = EACTIVE`, RPWM all-on, then
/// `SETPWRMODE(ACTIVE)`.
pub async fn fwlps_leave(io: &impl Io, mailbox: &mut Mailbox) -> Result<Sent, Error> {
    mailbox.ps_active = true;
    set_rpwm(io, FW_PS_STATE_ALL_ON).await?;
    mailbox
        .fill(io, H2C_SETPWRMODE, &pwrmode(PsMode::Active))
        .await
}

/// `rtl_lps_set_psmode(EAUTOPS)` → `_rtl92ee_fwlps_enter`
/// (`low_power_enable` false): `dot11_psmode = EAUTOPS` first, so the
/// `SETPWRMODE(DTIM)` is dropped by the H2C gate (returned), then RPWM
/// RF-off.
pub async fn fwlps_enter(io: &impl Io, mailbox: &mut Mailbox) -> Result<Sent, Error> {
    mailbox.ps_active = false;
    let sent = mailbox
        .fill(io, H2C_SETPWRMODE, &pwrmode(PsMode::Dtim))
        .await?;
    set_rpwm(io, FW_PS_STATE_RF_OFF).await?;
    Ok(sent)
}

/// `sta_entry->wireless_mode` of a 2.4 GHz station (`rtl_op_sta_add`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WirelessMode {
    B,
    G,
    N24,
}

/// Peer facts `rtl92ee_update_hal_rate_mask` reads from `ieee80211_sta`
/// (mac80211's intersected station HT capability).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    /// `supp_rates[0]`: bits 0–3 CCK 1/2/5.5/11, 4–11 OFDM.
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

/// `RATR_INX_WIRELESS_*` → `_rtl92ee_mrate_idx_to_arfr_id`.
pub const ARFR_NGB: u8 = 0;
pub const ARFR_NB: u8 = 2;
pub const ARFR_GB: u8 = 6;
pub const ARFR_B: u8 = 8;

/// `rtl92ee_update_hal_rate_mask` for the INFRA station (MACID 0,
/// `rf_type` 2T2R). `bw40` is `mac->bw_40` (station `curtxbw_40mhz`);
/// `rssi_level` is the DM level (0 = `DM_RATR_STA_INIT` at association).
/// Returns the 7-byte `H2C_92E_RA_MASK` body (its `ratr_index` is
/// `payload[1] & 0x7f`); the caller then sets `REG_BCN_CTRL` BIT(3).
pub fn rate_mask(peer: &Peer, bw40: bool, rssi_level: u8, update_bw: bool) -> [u8; 7] {
    let mut bitmap = u32::from(peer.legacy);
    if let Some(rx) = peer.ht {
        bitmap |= (u32::from(rx[1]) << 20) | (u32::from(rx[0]) << 12);
    }
    let mut sgi = false;
    let arfr_id = match peer.mode() {
        WirelessMode::B => {
            bitmap &= if bitmap & 0xc != 0 { 0xd } else { 0xf };
            ARFR_B
        }
        WirelessMode::G => {
            bitmap &= match rssi_level {
                1 => 0x0000_0f00,
                2 => 0x0000_0ff0,
                _ => 0x0000_0ff5,
            };
            ARFR_GB
        }
        WirelessMode::N24 => {
            // rf_type 2T2R rows.
            bitmap &= match (rssi_level, bw40) {
                (1, _) => 0x0f8f_0000,
                (2, _) => 0x0fff_f000,
                (_, true) => 0x0fff_f015,
                (_, false) => 0x0fff_f005,
            };
            // macid 0 ⇒ b_shortgi for the width's SGI.
            sgi = (bw40 && peer.sgi40) || (!bw40 && peer.sgi20);
            if bw40 {
                ARFR_NGB
            } else {
                ARFR_NB
            }
        }
    };
    let b = bitmap.to_le_bytes();
    [
        0,
        arfr_id | if sgi { 0x80 } else { 0 },
        u8::from(bw40) | u8::from(!update_bw) << 3,
        b[0],
        b[1],
        b[2],
        b[3],
    ]
}

/// Full-order rates (`DESC92C_RATE*` bit positions: 0..=11 legacy,
/// 12..=27 MCS0-15) a `H2C_92E_RA_MASK` payload lets the firmware RA
/// choose. `None` for an id this station never installs or a bitmap with
/// bits a legacy id cannot carry.
pub fn mask_rates(payload: &[u8; 7]) -> Option<u32> {
    let bitmap = u32::from_le_bytes([payload[3], payload[4], payload[5], payload[6]]);
    if bitmap & !0x0fff_ffff != 0 {
        return None;
    }
    match payload[1] & 0x7f {
        ARFR_GB | ARFR_B if bitmap >> 12 == 0 => Some(bitmap),
        ARFR_NGB | ARFR_NB => Some(bitmap),
        _ => None,
    }
}

/// `_rtl92ee_set_bcn_ctrl_reg` against the cached `reg_bcn_ctrl_val`.
pub fn set_bcn_ctrl(io: &impl Io, cached: &mut u8, set: u8, clear: u8) -> Result<(), Error> {
    *cached |= set;
    *cached &= !clear;
    io.write8(REG_BCN_CTRL, *cached)?;
    Ok(())
}

// ── PCI interrupt profile (`sw.c` masks, `hw.c` enable/disable/recognize) ──

pub const REG_HIMR: u16 = 0x00b0;
pub const REG_HISR: u16 = 0x00b4;
pub const REG_HIMRE: u16 = 0x00b8;
pub const REG_HISRE: u16 = 0x00bc;

/// `rtlpci->irq_mask[0]` (`sw.c`): PSTIMEOUT | C2HCMD | HIGHDOK | MGNTDOK |
/// BKDOK | BEDOK | VIDOK | VODOK | RDU | ROK (`rtl8192ee/reg.h` bits).
pub const IRQ_MASK0: u32 = (1 << 29) | (1 << 10) | 0xfc | 0x03;
/// `rtlpci->irq_mask[1]`: `IMR_RXFOVW` BIT(8).
pub const IRQ_MASK1: u32 = 1 << 8;

/// `rtl92ee_enable_interrupt`: HIMR/HIMRE only — no status clear, no
/// HSIMR and no `REG_C2HEVT_CLEAR` on this chip.
pub fn enable_interrupt(io: &impl Io) -> Result<(), Error> {
    io.write32(REG_HIMR, IRQ_MASK0)?;
    io.write32(REG_HIMRE, IRQ_MASK1)?;
    Ok(())
}

/// `rtl92ee_disable_interrupt` (`IMR_DISABLED`).
pub fn disable_interrupt(io: &impl Io) -> Result<(), Error> {
    io.write32(REG_HIMR, 0)?;
    io.write32(REG_HIMRE, 0)?;
    Ok(())
}

/// One `pci.c::_rtl_pci_interrupt` recognition pass for this chip: disable,
/// `rtl92ee_interrupt_recognized` (HISR/HISRE W1C under the masks), then
/// enable. The HSISR handler is 88EE/8723BE-only and the `IMR_C2HCMD`
/// firmware-event work is 8723AE-only; C2H arrives through the RX ring.
/// Ring service follows in the caller. Returns `(inta, intb)`.
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
