// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE host-to-firmware commands, LPS RPWM, the station RA mask and
//! the PCI interrupt profile.
//!
//! Exact `rtl8723be/fw.c`: `rtl8723be_fill_h2c_cmd` →
//! `_rtl8723be_fill_h2c_command` (the RTL8192EE box / extension-box
//! structure: byte-wise box writes, 4–7-byte commands write the zero-padded
//! four-byte extension box first, the `0x130` read after each HMETFR
//! re-check), `rtl8723be_set_fw_pwrmode_cmd`,
//! `rtl8723be_set_fw_media_status_rpt_cmd` and the
//! `rtl8723be_set_fw_rsvdpagepkt` location command; `rtl8723be/hw.c`:
//! `HW_VAR_SET_RPWM` (`REG_PCIE_HRPWM` 0x361), `_rtl8723be_fwlps_{enter,leave}`
//! (`low_power_enable` false), `rtl8723be_update_hal_rate_mask` (RF_1T1R
//! station: MCS0-7), `_rtl8723be_mrate_idx_to_arfr_id`,
//! `_rtl8723be_set_bcn_ctrl_reg`, `rtl8723be_{enable,disable}_interrupt`
//! and `rtl8723be_interrupt_recognized`; `rtl8723be/sw.c` masks and LPS
//! module defaults (`reg_fwctrl_lps = 2` ⇒ `FW_PS_MAX_MODE`,
//! `reg_max_lps_awakeintvl = 2`).
//!
//! Unlike RTL8192EE, `_rtl8723be_fill_h2c_command` has no power-save gate
//! and no `REG_CR == 0xEA` check: the LPS-enter `SETPWRMODE` reaches the
//! firmware. `rtl_lps_set_psmode` sets `smart_ps = 0` before the leave
//! action and `smart_ps = 2` before the enter action; with BT LPS control
//! (`btc_is_bt_ctrl_lps`, coexistence-owned) `SMART_PS` is 0 and the mode,
//! byte 5 and the power state come from the coexistence state
//! ([`BtLps`]).
//!
//! Differences from Linux: a full HMETFR wait (Linux silently drops the
//! command) is an error here and poisons the mailbox; a mailbox only exists
//! after a successful download, which is Linux's `fw_ready` gate. The
//! `h2c_setinprogress` spin is unnecessary: the owner serialises commands.

use crate::rtlwifi::firmware_transport::{Error as AccessError, Io};
use crate::rtlwifi::prepare::Error;

pub use super::super::rtl8192ee::h2c::{Peer, WirelessMode};

pub const REG_HMETFR: u16 = 0x01cc;
pub const REG_HMEBOX_0: u16 = 0x01d0;
pub const REG_HMEBOX_EXT_0: u16 = 0x01f0;
/// `rtl8723be/reg.h` `REG_PCIE_HRPWM`.
pub const REG_PCIE_HRPWM: u16 = 0x0361;
pub const REG_BCN_CTRL: u16 = 0x0550;
/// Read (and discarded) after each HMETFR re-check, as Linux's debug print.
const REG_DEBUG_130: u16 = 0x0130;

/// `enum rtl8723b_h2c_cmd` ids used by the station owner (`fw.h`).
pub const H2C_RSVDPAGE: u8 = 0x00;
pub const H2C_MSRRPT: u8 = 0x01;
pub const H2C_KEEP_ALIVE_CTRL: u8 = 0x03;
pub const H2C_SETPWRMODE: u8 = 0x20;
pub const H2C_RA_MASK: u8 = 0x40;
pub const H2C_RSSIBE_REPORT: u8 = 0x42;

/// `FW_PS_TOGGLE`; `FW_PS_STATE_{ALL_ON,RF_OFF}` are `FW_PS_CLOCK_ON`.
pub const FW_PS_TOGGLE: u8 = 1 << 7;
pub const FW_PS_STATE_ALL_ON: u8 = 0;
pub const FW_PS_STATE_RF_OFF: u8 = 0;
/// `FW_PWR_STATE_ACTIVE` = `FW_PS_RF_ON | FW_PS_REGISTER_ACTIVE`.
pub const FW_PWR_STATE_ACTIVE: u8 = (1 << 2) | (1 << 3);
pub const FW_PWR_STATE_RF_OFF: u8 = 0;
/// `sw.c`: `reg_max_lps_awakeintvl = 2` (only the DTIM mode reads it).
pub const MAX_LPS_AWAKE_INTERVAL: u8 = 2;
/// `H2C_PWEMODE_LENGTH`.
pub const PWRMODE_LENGTH: usize = 7;

/// HMETFR wait: one check plus 99 × 10 us retries (`wait_h2c_limmit`).
const HMETFR_CHECKS: u32 = 100;

/// `rtlhal->last_hmeboxnum` and a poison bit set by a failed command.
#[derive(Debug, Default)]
pub struct Mailbox {
    next: u8,
    pub failed: bool,
}

impl Mailbox {
    pub fn next_box(&self) -> u8 {
        self.next
    }

    /// `rtl8723be_fill_h2c_cmd` → `_rtl8723be_fill_h2c_command`.
    pub async fn fill(&mut self, io: &impl Io, id: u8, payload: &[u8]) -> Result<(), Error> {
        if self.failed || payload.is_empty() || payload.len() > 7 {
            return Err(Error::State);
        }
        self.failed = true;
        let boxnum = self.next;
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
        Ok(())
    }
}

/// `rtl8723be_set_fw_media_status_rpt_cmd` payload (INFRA station, MACID 0,
/// `MACID_IND` 0).
pub fn media_status(connected: bool) -> [u8; 3] {
    [u8::from(connected), 0, 0]
}

/// `wifi.h` `FW_PS_*_MODE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PsMode {
    Active,
    Min,
    /// `sw.c` `reg_fwctrl_lps = 2` ⇒ `fwctrl_psmode`.
    Max,
    Dtim,
}

/// The coexistence state `rtl8723be_set_fw_pwrmode_cmd` reads when
/// `btc_is_bt_ctrl_lps` is true (`get_btc_status()` is always true on this
/// chip).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BtLps {
    /// `btc_is_bt_lps_on`.
    pub lps_on: bool,
    /// `btc_get_lps_val`.
    pub lps_val: u8,
    /// `btc_get_rpwm_val`.
    pub rpwm_val: u8,
}

/// `rtl8723be_set_fw_pwrmode_cmd` for a non-P2P station. `smart_ps` is
/// `ppsc->smart_ps` (0 on leave, 2 on enter); `bt` is `Some` when BT
/// controls LPS.
pub fn pwrmode(mut mode: PsMode, smart_ps: u8, bt: Option<BtLps>) -> [u8; PWRMODE_LENGTH] {
    if let Some(bt) = bt {
        mode = if bt.lps_on {
            PsMode::Min
        } else {
            PsMode::Active
        };
    }
    let (mut rlbm, mut awake) = match mode {
        PsMode::Min => (0u8, 2u8),
        PsMode::Max => (1, 2),
        PsMode::Dtim => (2, MAX_LPS_AWAKE_INTERVAL),
        PsMode::Active => (2, 4),
    };
    let (byte5, state) = if mode == PsMode::Active {
        (0x40, FW_PWR_STATE_ACTIVE)
    } else if let Some(bt) = bt {
        if rlbm == 2 && bt.lps_val & (1 << 4) != 0 {
            awake = 2;
            rlbm = 2;
        }
        (bt.lps_val, bt.rpwm_val)
    } else {
        (0x40, FW_PWR_STATE_RF_OFF)
    };
    let smart = if bt.is_some() { 0 } else { smart_ps & 0xf };
    [
        u8::from(mode != PsMode::Active),
        (rlbm & 0xf) | (smart << 4),
        awake,
        0,
        state,
        byte5,
        0,
    ]
}

/// `rtl8723be_set_fw_rsvdpagepkt` location command (`H2C_8723B_RSVDPAGE`,
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

/// `rtl_lps_set_psmode(EACTIVE)` → `_rtl8723be_fwlps_leave`
/// (`low_power_enable` false): `smart_ps = 0`, RPWM all-on, then
/// `SETPWRMODE(ACTIVE)` (`fw_current_inpsmode = false` is the caller's).
pub async fn fwlps_leave(
    io: &impl Io,
    mailbox: &mut Mailbox,
    bt: Option<BtLps>,
) -> Result<[u8; PWRMODE_LENGTH], Error> {
    set_rpwm(io, FW_PS_STATE_ALL_ON).await?;
    let cmd = pwrmode(PsMode::Active, 0, bt);
    mailbox.fill(io, H2C_SETPWRMODE, &cmd).await?;
    Ok(cmd)
}

/// `rtl_lps_set_psmode(EAUTOPS)` → `_rtl8723be_fwlps_enter`
/// (`low_power_enable` false): `smart_ps = 2`, `SETPWRMODE(fwctrl_psmode
/// = MAX)`, then RPWM RF-off. Returns the command for
/// `btc_record_pwr_mode`.
pub async fn fwlps_enter(
    io: &impl Io,
    mailbox: &mut Mailbox,
    bt: Option<BtLps>,
) -> Result<[u8; PWRMODE_LENGTH], Error> {
    let cmd = pwrmode(PsMode::Max, 2, bt);
    mailbox.fill(io, H2C_SETPWRMODE, &cmd).await?;
    set_rpwm(io, FW_PS_STATE_RF_OFF).await?;
    Ok(cmd)
}

/// `_rtl8723be_mrate_idx_to_arfr_id` values for the ids this station uses
/// (`RATR_INX_WIRELESS_NGB` 1, `GB` 6, `B` 8).
pub const ARFR_NGB: u8 = 1;
pub const ARFR_GB: u8 = 6;
pub const ARFR_B: u8 = 8;

/// `rtl8723be_update_hal_rate_mask` for the INFRA station (MACID 0,
/// `rf_type` RF_1T1R). `bw40` is `mac->bw_40`; `rssi_level` is the DM
/// level (0 = `DM_RATR_STA_INIT` at association). Returns the 7-byte
/// `H2C_8723B_RA_MASK` body; the caller then sets `REG_BCN_CTRL` BIT(3).
/// Every N station uses `RATR_INX_WIRELESS_NGB` at either width.
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
            bitmap &= match (rssi_level, bw40) {
                (1, _) => 0x000f_0000,
                (2, _) => 0x000f_f000,
                (_, true) => 0x000f_f015,
                (_, false) => 0x000f_f005,
            };
            sgi = (bw40 && peer.sgi40) || (!bw40 && peer.sgi20);
            ARFR_NGB
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
/// 12..=19 MCS0-7) a `H2C_8723B_RA_MASK` payload lets the firmware RA
/// choose. `None` for an id this station never installs or bits a 1T1R
/// station cannot carry.
pub fn mask_rates(payload: &[u8; 7]) -> Option<u32> {
    let bitmap = u32::from_le_bytes([payload[3], payload[4], payload[5], payload[6]]);
    if bitmap & !0x000f_ffff != 0 {
        return None;
    }
    match payload[1] & 0x7f {
        ARFR_GB | ARFR_B if bitmap >> 12 == 0 => Some(bitmap),
        ARFR_NGB => Some(bitmap),
        _ => None,
    }
}

/// `_rtl8723be_set_bcn_ctrl_reg` against the cached `reg_bcn_ctrl_val`.
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

/// `IMR_HSISR_IND_ON_INT` (`rtl8723be/reg.h`).
pub const IMR_HSISR_IND_ON_INT: u32 = 1 << 15;
/// `rtlpci->irq_mask[0]` (`sw.c`): PSTIMEOUT | HSISR_IND_ON_INT | C2HCMD |
/// HIGHDOK | MGNTDOK | BKDOK | BEDOK | VIDOK | VODOK | RDU | ROK.
pub const IRQ_MASK0: u32 = (1 << 29) | IMR_HSISR_IND_ON_INT | (1 << 10) | 0xfc | 0x03;
/// `rtlpci->irq_mask[1]`: `IMR_RXFOVW` BIT(8).
pub const IRQ_MASK1: u32 = 1 << 8;
/// `rtlpci->sys_irq_mask`: `HSIMR_PDN_INT_EN | HSIMR_RON_INT_EN`.
pub const SYS_IRQ_MASK: u32 = (1 << 7) | (1 << 6);

/// `rtl8723be_enable_interrupt`: HIMR, HIMRE, then HSIMR.
pub fn enable_interrupt(io: &impl Io) -> Result<(), Error> {
    io.write32(REG_HIMR, IRQ_MASK0)?;
    io.write32(REG_HIMRE, IRQ_MASK1)?;
    io.write32(REG_HSIMR, SYS_IRQ_MASK)?;
    Ok(())
}

/// `rtl8723be_disable_interrupt` (`IMR_DISABLED`; HSIMR is left as is).
pub fn disable_interrupt(io: &impl Io) -> Result<(), Error> {
    io.write32(REG_HIMR, 0)?;
    io.write32(REG_HIMRE, 0)?;
    Ok(())
}

/// One `pci.c::_rtl_pci_interrupt` recognition pass for this chip: disable,
/// `rtl8723be_interrupt_recognized` (HISR/HISRE W1C under the masks), the
/// `_rtl_pci_hs_interrupt` HSISR write (`old | sys_irq_mask`, 8723BE/88EE
/// only) when `IMR_HSISR_IND_ON_INT` is set, then enable. A zero `inta`
/// skips straight to enable, as Linux's `goto done`. The `IMR_C2HCMD`
/// firmware-event work is 8723AE-only; C2H arrives through the RX ring.
/// Returns `(inta, intb)`.
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
    if inta != 0 && inta & IMR_HSISR_IND_ON_INT != 0 {
        let hsisr = io.read8(REG_HSISR)?;
        io.write8(REG_HSISR, hsisr | SYS_IRQ_MASK as u8)?;
    }
    enable_interrupt(io)?;
    Ok((inta, intb))
}
