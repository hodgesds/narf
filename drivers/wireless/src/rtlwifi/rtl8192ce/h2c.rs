// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192CE / RTL8188CE host-to-firmware commands and interrupt profile.
//!
//! - [`Mailbox::fill`] — `rtl8192c/fw_common.c::rtl92c_fill_h2c_cmd` /
//!   `_rtl92c_fill_h2c_command`: the command is copied into a zeroed 8-byte
//!   buffer; one write attempt (Linux's `wait_writeh2c_limmit` loop never
//!   repeats: it breaks or succeeds) with `_rtl92c_check_fw_read_last_h2c`
//!   (`REG_HMETFR` bit `boxnum` clear **and** `REG_MCUTST_1 + boxnum` zero)
//!   with up to 99 re-checks 10 us apart, each followed by Linux's `0x1BF`
//!   read; byte-wise box writes (1–3 bytes: BIT(7) of the id clear; 4–5
//!   bytes: BIT(7) set, the first two bytes into `REG_HMEBOX_EXT_n` first);
//!   `last_hmeboxnum` rotation. Unlike Linux (which logs and returns), a
//!   box the firmware never drained or a length outside 1..=5 poisons the
//!   mailbox. This family has no power-save gate in the fill path.
//! - [`pwrmode`] / [`joinbss`] — `rtl92c_set_fw_pwrmode_cmd` (mode, smart
//!   PS 1 — no P2P — and `reg_max_lps_awakeintvl` 5) and
//!   `rtl92c_set_fw_joinbss_report_cmd`.
//! - [`rate_mask`] — `rtl92ce_update_hal_rate_mask` for a 2.4 GHz station
//!   (`macid` 0, `curtxbw_40mhz = mac->bw_40`).
//! - [`set_rpwm`] — `HW_VAR_SET_RPWM` (`REG_PCIE_HRPWM` 0x3dc toggle).
//! - Interrupts: `rtl92ce_enable_interrupt` (`irq_mask` from `sw.c`),
//!   `rtl92ce_disable_interrupt` (`IMR8190_DISABLED`) and
//!   `rtl92ce_interrupt_recognized` (HISR under mask, W1C; HISRE is
//!   neither read nor cleared, as Linux).

use super::version::RfType;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const REG_HMEBOX_EXT_0: u16 = 0x0088;
pub const REG_MCUTST_1: u16 = 0x01c0;
pub const REG_HMETFR: u16 = 0x01cc;
pub const REG_HMEBOX_0: u16 = 0x01d0;
pub const REG_PCIE_HRPWM: u16 = 0x03dc;
pub const REG_HIMR: u16 = 0x0120;
pub const REG_HISR: u16 = 0x0124;
pub const REG_HIMRE: u16 = 0x0128;
pub const REG_HISRE: u16 = 0x012c;

/// `enum rtl_h2c_cmd` (`wifi.h`).
pub const H2C_SETPWRMODE: u8 = 1;
pub const H2C_JOINBSSRPT: u8 = 2;
pub const H2C_RSVDPAGE: u8 = 3;
pub const H2C_RA_MASK: u8 = 6;

/// `FW_PS_*_MODE`.
pub const FW_PS_ACTIVE_MODE: u8 = 0;
pub const FW_PS_DTIM_MODE: u8 = 3;
/// `rtl92c_init_sw_vars` `reg_max_lps_awakeintvl`.
pub const MAX_LPS_AWAKE_INTERVAL: u8 = 5;
/// `RT_MEDIA_CONNECT` / `RT_MEDIA_DISCONNECT`.
pub const MEDIA_CONNECT: u8 = 1;
pub const MEDIA_DISCONNECT: u8 = 0;

/// `rtl92c_init_sw_vars` `irq_mask[0]`: ROK | VODOK | VIDOK | BEDOK |
/// BKDOK | MGNTDOK | HIGHDOK | BDOK | RDU | RXFOVW.
pub const IRQ_MASK0: u32 = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x40 | 0x100 | 0x200 | 0x800 | 0x1000;
/// `irq_mask[1]`: CPWM | C2HCMD.
pub const IRQ_MASK1: u32 = (1 << 8) | (1 << 9);

const WAIT_READ: u8 = 100;

/// Outcome of one fill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    /// Written to the given box.
    Box(u8),
}

/// `rtlhal->last_hmeboxnum` plus a poison bit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mailbox {
    next: u8,
    pub failed: bool,
}

async fn fw_read_last(io: &impl Io, boxnum: u8) -> Result<bool, Error> {
    let hmetfr = io.read8(REG_HMETFR)?;
    let mcutst = io.read8(REG_MCUTST_1 + u16::from(boxnum))?;
    Ok((hmetfr >> boxnum) & 1 == 0 && mcutst == 0)
}

impl Mailbox {
    /// `rtlhal->last_hmeboxnum = 0` (after a successful download).
    pub const fn new() -> Self {
        Self {
            next: 0,
            failed: false,
        }
    }

    pub fn next_box(&self) -> u8 {
        self.next
    }

    /// `rtl92c_fill_h2c_cmd(element_id, len, payload)`.
    pub async fn fill(&mut self, io: &impl Io, id: u8, payload: &[u8]) -> Result<Sent, Error> {
        if self.failed {
            return Err(Error::State);
        }
        if payload.is_empty() || payload.len() > 5 {
            self.failed = true;
            return Err(Error::Descriptor);
        }
        let mut buf = [0u8; 8];
        buf[..payload.len()].copy_from_slice(payload);
        // Linux's outer `while (!bwrite_sucess)` runs once: an undrained box
        // breaks out, a written one sets `bwrite_sucess`.
        let boxnum = self.next;
        let box_reg = REG_HMEBOX_0 + 4 * u16::from(boxnum);
        let ext_reg = REG_HMEBOX_EXT_0 + 2 * u16::from(boxnum);
        let mut read_left = WAIT_READ;
        let mut read = fw_read_last(io, boxnum).await?;
        while !read {
            read_left -= 1;
            if read_left == 0 {
                break;
            }
            io.delay_us(10).await;
            read = fw_read_last(io, boxnum).await?;
            io.read8(0x1bf)?;
        }
        if read {
            let mut content = [id, 0, 0, 0];
            if payload.len() <= 3 {
                content[0] &= !(1 << 7);
                content[1..1 + payload.len()].copy_from_slice(&buf[..payload.len()]);
            } else {
                content[0] |= 1 << 7;
                content[1..payload.len() - 1].copy_from_slice(&buf[2..payload.len()]);
                for (i, b) in buf[..2].iter().enumerate() {
                    io.write8(ext_reg + i as u16, *b)?;
                }
            }
            for (i, b) in content.iter().enumerate() {
                io.write8(box_reg + i as u16, *b)?;
            }
            self.next = (boxnum + 1) % 4;
            return Ok(Sent::Box(boxnum));
        }
        self.failed = true;
        Err(Error::PacketTimeout)
    }
}

/// `rtl92c_set_fw_pwrmode_cmd(mode)` payload.
pub const fn pwrmode(mode: u8) -> [u8; 3] {
    [mode, 1, MAX_LPS_AWAKE_INTERVAL]
}

/// `rtl92c_set_fw_joinbss_report_cmd(mstatus)` payload.
pub const fn joinbss(mstatus: u8) -> [u8; 1] {
    [mstatus]
}

/// `HW_VAR_SET_RPWM`: BIT(7) toggled against the current value.
pub async fn set_rpwm(io: &impl Io, value: u8) -> Result<(), Error> {
    let cur = io.read8(REG_PCIE_HRPWM)?;
    io.delay_us(1).await;
    if cur & (1 << 7) != 0 {
        io.write8(REG_PCIE_HRPWM, value)?;
    } else {
        io.write8(REG_PCIE_HRPWM, value | (1 << 7))?;
    }
    Ok(())
}

/// `sta_entry->wireless_mode` for a 2.4 GHz peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WirelessMode {
    B,
    G,
    N24,
}

/// The `ieee80211_sta` fields `rtl92ce_update_hal_rate_mask` reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    pub mode: WirelessMode,
    /// `supp_rates[0]` (12 legacy bits).
    pub supp_rates: u32,
    /// `ht_cap.mcs.rx_mask[0..2]`.
    pub rx_mask: [u8; 2],
    pub sgi20: bool,
    pub sgi40: bool,
}

pub const RATR_INX_WIRELESS_NGB: u8 = 0;
pub const RATR_INX_WIRELESS_GB: u8 = 4;
pub const RATR_INX_WIRELESS_B: u8 = 6;

/// `rtl92ce_update_hal_rate_mask` payload for a station (`macid` 0,
/// `curtxbw_40mhz = bw40`). `update_bw` is unused by Linux on this chip.
pub fn rate_mask(peer: &Peer, rf_type: RfType, bw40: bool, rssi_level: u8) -> [u8; 5] {
    let mut bitmap =
        peer.supp_rates | (u32::from(peer.rx_mask[1]) << 20) | (u32::from(peer.rx_mask[0]) << 12);
    let mut shortgi = false;
    let index = match peer.mode {
        WirelessMode::B => {
            bitmap &= if bitmap & 0x0c != 0 { 0x0d } else { 0x0f };
            RATR_INX_WIRELESS_B
        }
        WirelessMode::G => {
            bitmap &= match rssi_level {
                1 => 0x0000_0f00,
                2 => 0x0000_0ff0,
                _ => 0x0000_0ff5,
            };
            RATR_INX_WIRELESS_GB
        }
        WirelessMode::N24 => {
            let (low, mid, high) = match (rf_type, bw40) {
                (RfType::T1R1, true) => (0x000f_0000, 0x000f_f000, 0x000f_f015),
                (RfType::T1R1, false) => (0x000f_0000, 0x000f_f000, 0x000f_f005),
                (RfType::T2R2, true) => (0x0f0f_0000, 0x0f0f_f000, 0x0f0f_f015),
                (RfType::T2R2, false) => (0x0f0f_0000, 0x0f0f_f000, 0x0f0f_f005),
            };
            bitmap &= match rssi_level {
                1 => low,
                2 => mid,
                _ => high,
            };
            if (bw40 && peer.sgi40) || (!bw40 && peer.sgi20) {
                shortgi = true;
            }
            RATR_INX_WIRELESS_NGB
        }
    };
    let word = (bitmap & 0x0fff_ffff) | (u32::from(index) << 28);
    let b = word.to_le_bytes();
    [
        b[0],
        b[1],
        b[2],
        b[3],
        if shortgi { 0x20 } else { 0 } | 0x80,
    ]
}

/// `rtl92ce_enable_interrupt`.
pub fn enable_interrupt(io: &impl Io) -> Result<(), Error> {
    io.write32(REG_HIMR, IRQ_MASK0)?;
    io.write32(REG_HIMRE, IRQ_MASK1)?;
    Ok(())
}

/// `rtl92ce_disable_interrupt`.
pub fn disable_interrupt(io: &impl Io) -> Result<(), Error> {
    io.write32(REG_HIMR, 0)?;
    io.write32(REG_HIMRE, 0)?;
    Ok(())
}

/// `rtl92ce_interrupt_recognized`: `inta = HISR & irq_mask[0]`, written back.
pub fn recognize(io: &impl Io) -> Result<u32, Error> {
    let inta = io.read32(REG_HISR)? & IRQ_MASK0;
    io.write32(REG_HISR, inta)?;
    Ok(inta)
}
