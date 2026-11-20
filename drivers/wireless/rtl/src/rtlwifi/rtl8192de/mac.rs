// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE operational MAC (`_rtl92de_init_mac` after the LLT,
//! `_rtl92de_hw_configure`, interrupt control, and the `rtl92de_hw_init`
//! station-identity / CAM steps).
//!
//! Linux `rtl8192de/hw.c::_rtl92de_init_mac` after [`super::llt`] and
//! the power prefix ([`super::power`]), `_rtl92de_hw_configure`, and
//! the `rtl92de_hw_init` steps that need no PHY/RF state. Deferred to
//! the retained packet owner / `Prepared` integration, as for
//! RTL8192CE: the TX/RX descriptor physical addresses
//! (`REG_BCNQ_DESA` … `REG_RX_DESA`, from the OS ring DMA addresses).
//! Omitted with reason: `_rtl92de_gen_refresh_led_state` (LED only).
//! `rtl92d_phy_config_maccoexist_rfpage` is included ([`maccoexist_rfpage`])
//! since it is plain register writes. The `rtl92de_hw_init` early-mode
//! block ([`early_mode`]), the ASPM back-door
//! ([`enable_aspm_back_door`]) and the hardware-security enable
//! ([`enable_hw_security_config`]) are included the same way; with
//! software crypto the security enable writes nothing, so
//! `REG_SECCFG` stays 0 as in [`station_identity`].
//!
//! Two faithful departures from the RTL8192CE port are deliberate.
//! The `REG_APSD_CTRL` BIT(7) poll waits *for* the bit, exactly as
//! Linux's `do { retry++; read; } while (retry < 200 && !BIT(7))` —
//! and, like Linux, proceeds after 200 reads whether or not the bit
//! set. And `REG_FAST_EDCA_CTRL` is a word write (`0x6666`), as Linux
//! writes it here (the 92CE port wrote a dword).

use super::power::REG_CR;
use super::{ampdu_factor_base, MacPhyMode};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// `rtl92d_init_sw_vars` `receive_config`: APPFCS | AMF | ADF |
/// APP_MIC | APP_ICV | AICV | ACRC32 | AB | AM | APM |
/// APP_PHYST_RXFF | HTC_LOC_CTRL (`rtl8192de/sw.c`).
pub const RCR: u32 = 0xf000_6b0e;
/// `RCR_ACRC32 | RCR_AICV`, cleared from the RCR read back after
/// `rtl92c_phy_mac_config` in `rtl92de_hw_init`.
pub const RCR_ACRC32_AICV: u32 = (1 << 8) | (1 << 9);
/// `transmit_config`: CFENDFORM | BIT(12) | BIT(13)
/// (`rtl8192de/sw.c`).
pub const TCR: u32 = 0x0000_3200;
/// `REG_RRSR`: `RATE_ALL_CCK | RATE_ALL_OFDM_AG`
/// (`rtl8192d/reg.h`: CCK `0x1|0x2|0x4|0x8`, OFDM `0x10..0x800`).
pub const RRSR: u32 = 0x0000_0fff;
/// `rtl92de_init_sw_vars` interrupt masks (`rtl8192de/sw.c`):
/// mask[0] = ROK|VODOK|VIDOK|BEDOK|BKDOK|MGNTDOK|HIGHDOK|BDOK|RDU|
/// RXFOVW; mask[1] = CPWM|C2HCMD.
pub const IRQ_MASK: (u32, u32) = (0x0000_1b7f, 0x0000_0300);
/// `IMR8190_DISABLED` (`rtl8192d/reg.h`).
pub const IRQ_DISABLED: u32 = 0x0;
/// `rtl_cam_reset_all_entry`: `BIT(31) | BIT(30)` into `REG_CAMCMD`.
pub const CAM_RESET: u32 = 0xc000_0000;

pub const REG_HIMR: u16 = 0x0120;
pub const REG_HISR: u16 = 0x0124;
pub const REG_HIMRE: u16 = 0x0128;
pub const REG_HISRE: u16 = 0x012c;
pub const REG_TRXDMA_CTRL: u16 = 0x010c;
pub const REG_TRXFF_BNDY: u16 = 0x0114;
pub const REG_MCUTST_1: u16 = 0x01c0;
pub const REG_PCIE_CTRL_REG: u16 = 0x0300;
pub const REG_INT_MIG: u16 = 0x0304;
pub const REG_FWHW_TXQ_CTRL: u16 = 0x0420;
pub const REG_HWSEQ_CTRL: u16 = 0x0423;
pub const REG_SPEC_SIFS: u16 = 0x0428;
pub const REG_RL: u16 = 0x042a;
pub const REG_DARFRC: u16 = 0x0430;
pub const REG_RARFRC: u16 = 0x0438;
pub const REG_RRSR: u16 = 0x0440;
pub const REG_AGGLEN_LMT: u16 = 0x0458;
pub const REG_AMPDU_MIN_SPACE: u16 = 0x045c;
pub const REG_FAST_EDCA_CTRL: u16 = 0x0460;
pub const REG_INIRTS_RATE_SEL: u16 = 0x0480;
pub const REG_BAR_MODE_CTRL: u16 = 0x04cc;
pub const REG_PIFS: u16 = 0x0512;
pub const REG_SIFS_CTX: u16 = 0x0514;
pub const REG_SIFS_TRX: u16 = 0x0516;
pub const REG_AGGR_BREAK_TIME: u16 = 0x051a;
pub const REG_SLOT: u16 = 0x051b;
pub const REG_TBTT_PROHIBIT: u16 = 0x0540;
pub const REG_NAV_PROT_LEN: u16 = 0x0546;
pub const REG_BCN_CTRL: u16 = 0x0550;
pub const REG_ATIMWND: u16 = 0x055a;
pub const REG_BCN_MAX_ERR: u16 = 0x055d;
pub const REG_DMC: u16 = 0x05f0;
pub const REG_APSD_CTRL: u16 = 0x0600;
pub const REG_BWOPMODE: u16 = 0x0603;
pub const REG_TCR: u16 = 0x0604;
pub const REG_RCR: u16 = 0x0608;
pub const REG_RX_PKT_LIMIT: u16 = 0x060c;
pub const REG_MACID: u16 = 0x0610;
pub const REG_MAR: u16 = 0x0620;
pub const REG_MAC_SPEC_SIFS: u16 = 0x063a;
pub const REG_ACKTO: u16 = 0x0640;
pub const REG_CAMCMD: u16 = 0x0670;
pub const REG_SECCFG: u16 = 0x0680;
/// `REG_PCIE_CTRL_REG + 3` value written by `_rtl92de_init_mac`
/// (early-mode disable is the `0x4d0` byte below it).
pub const PCIE_CTRL_REG_3: u8 = 0x33;
/// `REG_EARLYMODE_CONTROL` (early-mode control byte).
pub const REG_EARLYMODE_CTRL: u16 = 0x04d0;
/// `SCR_TXUSEDK` / `SCR_RXUSEDK` / `SCR_TXENCENABLE` /
/// `SCR_RXENCENABLE` / `SCR_TXBCUSEDK` / `SCR_RXBCUSEDK`
/// (`rtl8192de/reg.h`).
pub const SCR_TXUSEDK: u8 = 1 << 0;
pub const SCR_RXUSEDK: u8 = 1 << 1;
pub const SCR_TXENCENABLE: u8 = 1 << 2;
pub const SCR_RXENCENABLE: u8 = 1 << 3;
pub const SCR_TXBCUSEDK: u8 = 1 << 6;
pub const SCR_RXBCUSEDK: u8 = 1 << 7;
/// `REG_BWOPMODE` value: `BW_OPMODE_20MHZ` (`rtl8192d/reg.h`).
pub const BWOPMODE_20MHZ: u8 = 1 << 2;

fn w8(io: &impl Io, reg: u16, value: u8) -> Result<(), Error> {
    Ok(io.write8(reg, value)?)
}
fn w16(io: &impl Io, reg: u16, value: u16) -> Result<(), Error> {
    Ok(io.write16(reg, value)?)
}
fn w32(io: &impl Io, reg: u16, value: u32) -> Result<(), Error> {
    Ok(io.write32(reg, value)?)
}
fn byte(io: &impl Io, reg: u16, value: u8) -> Result<(), Error> {
    io.write8(reg, value)?;
    if io.read8(reg)? != value {
        return Err(Error::Readback);
    }
    Ok(())
}
fn dword(io: &impl Io, reg: u16, value: u32) -> Result<(), Error> {
    io.write32(reg, value)?;
    if io.read32(reg)? != value {
        return Err(Error::Readback);
    }
    Ok(())
}

/// `rtl92d_phy_config_maccoexist_rfpage`
/// (`rtl8192d/phy_common.c`): dual-dual writes `REG_DMC = 0`,
/// `REG_RX_PKT_LIMIT = 0x08`, `REG_TRXFF_BNDY+2 = 0x13ff`;
/// dual-single writes `REG_DMC = 0xf8` with the same limit and
/// boundary; single writes `REG_DMC = 0`, `REG_RX_PKT_LIMIT = 0x10`,
/// `REG_TRXFF_BNDY+2 = 0x27ff`.
pub fn maccoexist_rfpage(io: &impl Io, mode: MacPhyMode) -> Result<(), Error> {
    let (dmc, limit, bndy) = match mode {
        MacPhyMode::DualMacDualPhy => (0x00, 0x08, 0x13ff),
        MacPhyMode::DualMacSinglePhy => (0xf8, 0x08, 0x13ff),
        MacPhyMode::SingleMacSinglePhy => (0x00, 0x10, 0x27ff),
    };
    w8(io, REG_DMC, dmc)?;
    w8(io, REG_RX_PKT_LIMIT, limit)?;
    w16(io, REG_TRXFF_BNDY + 2, bndy)
}

/// `_rtl92de_init_mac` after the LLT, ring bases excluded. The
/// `REG_APSD_CTRL` BIT(7) poll continues Linux's shape: up to 200
/// reads waiting for the bit, proceeding either way.
pub async fn init_mac(io: &impl Io, mode: MacPhyMode) -> Result<(), Error> {
    // W1C status clear; not an acknowledgement of serviced work.
    w32(io, REG_HISR, u32::MAX)?;
    w8(io, REG_HISRE, 0xff)?;
    maccoexist_rfpage(io, mode)?;
    let old = u16::from_le_bytes([io.read8(REG_TRXDMA_CTRL)?, io.read8(REG_TRXDMA_CTRL + 1)?]);
    w16(io, REG_TRXDMA_CTRL, (old & 0xf) | 0xf771)?;
    byte(io, REG_FWHW_TXQ_CTRL + 1, 0x1f)?;
    dword(io, REG_RCR, RCR)?;
    dword(io, REG_TCR, TCR)?;
    w8(io, REG_EARLYMODE_CTRL, 0x00)?;
    byte(io, REG_PCIE_CTRL_REG + 3, PCIE_CTRL_REG_3)?;
    dword(io, REG_INT_MIG, 0)?;
    let value = io.read8(REG_APSD_CTRL)?;
    w8(io, REG_APSD_CTRL, value & !(1 << 6))?;
    for _ in 0..200 {
        if io.read8(REG_APSD_CTRL)? & (1 << 7) != 0 {
            break;
        }
        io.delay_us(0).await;
    }
    dword(io, REG_MCUTST_1, 0)
}

/// `_rtl92de_hw_configure` (non-BT). Plain writes exactly as Linux;
/// `REG_AGGLEN_LMT` is the mode's AMPDU-factor base
/// ([`ampdu_factor_base`]). The `minspace_cfg` assignment by RF type
/// stores a driver variable and writes no register, so it is not
/// ported. `REG_BCN_CTRL` is `reg_bcn_ctrl_val` (`0x1f`).
pub fn hw_configure(io: &impl Io, mode: MacPhyMode) -> Result<(), Error> {
    w8(io, REG_INIRTS_RATE_SEL, 0x8)?;
    w8(io, REG_BWOPMODE, BWOPMODE_20MHZ)?;
    w32(io, REG_RRSR, RRSR)?;
    w8(io, REG_SLOT, 0x09)?;
    w8(io, REG_AMPDU_MIN_SPACE, 0x0)?;
    w16(io, REG_FWHW_TXQ_CTRL, 0x1f80)?;
    w16(io, REG_RL, 0x0707)?;
    w32(io, REG_BAR_MODE_CTRL, 0x0201_2802)?;
    w8(io, REG_HWSEQ_CTRL, 0xff)?;
    w32(io, REG_DARFRC, 0x0100_0000)?;
    w32(io, REG_DARFRC + 4, 0x0706_0504)?;
    w32(io, REG_RARFRC, 0x0100_0000)?;
    w32(io, REG_RARFRC + 4, 0x0706_0504)?;
    w32(io, REG_AGGLEN_LMT, ampdu_factor_base(mode))?;
    w8(io, REG_ATIMWND, 0x2)?;
    w8(io, REG_BCN_MAX_ERR, 0x0a)?;
    w8(io, REG_BCN_CTRL, 0x1f)?;
    w8(io, REG_TBTT_PROHIBIT + 1, 0xff)?;
    w8(io, REG_PIFS, 0x1c)?;
    w8(io, REG_AGGR_BREAK_TIME, 0x16)?;
    w16(io, REG_NAV_PROT_LEN, 0x0020)?;
    w16(io, REG_FAST_EDCA_CTRL, 0x6666)?;
    w8(io, REG_ACKTO, 0x40)?;
    w16(io, REG_SPEC_SIFS, 0x1010)?;
    w16(io, REG_MAC_SPEC_SIFS, 0x1010)?;
    w16(io, REG_SIFS_CTX, 0x1010)?;
    w16(io, REG_SIFS_TRX, 0x1010)?;
    w32(io, REG_MAR, 0xffff_ffff)?;
    w32(io, REG_MAR + 4, 0xffff_ffff)
}

/// `rtl92de_hw_init` after `rtl92c_phy_mac_config`: RCR read back with
/// `RCR_ACRC32 | RCR_AICV` cleared. Returns the new `receive_config`.
pub fn trim_receive_config(io: &impl Io) -> Result<u32, Error> {
    let rcr = io.read32(REG_RCR)? & !RCR_ACRC32_AICV;
    dword(io, REG_RCR, rcr)?;
    Ok(rcr)
}

/// The `rtl92de_hw_init` early-mode block (`rtl8192de/hw.c:913-931`):
/// `REG_TCR + 1` (`0x605`) always gains `0x30`; when early mode is
/// enabled (`rtlhal->earlymode_enable`,
/// [`super::lifecycle::SwVars::earlymode_enable`]) the early-mode
/// control byte gains `0x1f`, the packet-count byte (`0x4d3`) is
/// `0x80`, and `REG_TCR + 1` gains `0x40`. `_rtl92de_init_mac`
/// clears the control byte first ([`init_mac`]).
pub fn early_mode(io: &impl Io, enable: bool) -> Result<(), Error> {
    let tcr1 = io.read8(REG_TCR + 1)?;
    io.write8(REG_TCR + 1, tcr1 | 0x30)?;
    if enable {
        let em = io.read8(REG_EARLYMODE_CTRL)?;
        io.write8(REG_EARLYMODE_CTRL, em | 0x1f)?;
        io.write8(REG_EARLYMODE_CTRL + 3, 0x80)?;
        let tcr1 = io.read8(REG_TCR + 1)?;
        io.write8(REG_TCR + 1, tcr1 | 0x40)?;
    }
    Ok(())
}

/// `_rtl92de_enable_aspm_back_door` (`rtl8192de/hw.c:833-847`): the
/// DBI control writes (`0x34b`, `0x350`, `0x352`) with the
/// back-door byte (`0x349`) `0x1b` when the back door is supported
/// ([`super::lifecycle::AspmVars::support_backdoor`]) and `0x03`
/// otherwise.
pub fn enable_aspm_back_door(io: &impl Io, support_backdoor: bool) -> Result<(), Error> {
    io.write8(0x34b, 0x93)?;
    io.write16(0x350, 0x870c)?;
    io.write8(0x352, 0x1)?;
    io.write8(0x349, if support_backdoor { 0x1b } else { 0x03 })?;
    io.write16(0x350, 0x2718)?;
    io.write8(0x352, 0x1)?;
    Ok(())
}

/// Inputs to `rtl92de_enable_hw_security_config`
/// (`rtl8192de/hw.c:849-873`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HwSecurity {
    /// `rtlpriv->cfg->mod_params->sw_crypto`.
    pub sw_crypto: bool,
    /// `rtlpriv->sec.use_sw_sec`.
    pub use_sw_sec: bool,
    /// `rtlpriv->sec.use_defaultkey`.
    pub use_defaultkey: bool,
}

impl HwSecurity {
    /// The `REG_SECCFG` value, or `None` when software crypto leaves
    /// hardware encryption closed: either software-crypto flag
    /// returns before any write, so `REG_SECCFG` stays 0 (the
    /// in-tree station behaviour, [`station_identity`]). Otherwise
    /// TX/RX encryption enable plus the broadcast-key bits, with the
    /// default-key bits when a default key is in use.
    pub fn seccfg(self) -> Option<u8> {
        if self.sw_crypto || self.use_sw_sec {
            return None;
        }
        let mut value = SCR_TXENCENABLE | SCR_RXENCENABLE | SCR_RXBCUSEDK | SCR_TXBCUSEDK;
        if self.use_defaultkey {
            value |= SCR_TXUSEDK | SCR_RXUSEDK;
        }
        Some(value)
    }
}

/// `rtl92de_enable_hw_security_config`: with hardware security the
/// `REG_CR + 1` byte is `0x02` and `REG_SECCFG` takes
/// [`HwSecurity::seccfg`]; with software crypto nothing is written.
pub fn enable_hw_security_config(io: &impl Io, sec: HwSecurity) -> Result<(), Error> {
    let Some(value) = sec.seccfg() else {
        return Ok(());
    };
    w8(io, REG_CR + 1, 0x02)?;
    byte(io, REG_SECCFG, value)?;
    Ok(())
}

/// `rtl92de_enable_interrupt` / `rtl92de_disable_interrupt`
/// (`rtl8192de/hw.c`): HIMR/HIMRE from the `rtl92de_init_sw_vars`
/// masks, or `IMR8190_DISABLED` (0) when disabled.
pub fn enable_interrupt(io: &impl Io) -> Result<(), Error> {
    w32(io, REG_HIMR, IRQ_MASK.0)?;
    w32(io, REG_HIMRE, IRQ_MASK.1)
}

pub fn disable_interrupt(io: &impl Io) -> Result<(), Error> {
    w32(io, REG_HIMR, IRQ_DISABLED)?;
    w32(io, REG_HIMRE, IRQ_DISABLED)
}

/// `rtl_cam_reset_all_entry` (`cam.c`): `BIT(31) | BIT(30)` into
/// `REG_CAMCMD` (the `RWCAM` map, `rtl8192de/sw.c`).
pub fn cam_reset(io: &impl Io) -> Result<(), Error> {
    w32(io, REG_CAMCMD, CAM_RESET)
}

/// Software crypto (`REG_SECCFG` 0) and `HW_VAR_ETHER_ADDR`
/// (`rtl92d_set_hw_reg`, `rtl8192d/hw_common.c`): the station MAC
/// address into `REG_MACID`.
pub fn station_identity(io: &impl Io, mac: &[u8; 6]) -> Result<(), Error> {
    byte(io, REG_SECCFG, 0)?;
    station_address(io, mac)
}

/// `HW_VAR_ETHER_ADDR` alone: the station MAC address into
/// `REG_MACID`, leaving `REG_SECCFG` as
/// [`enable_hw_security_config`] programmed it.
pub fn station_address(io: &impl Io, mac: &[u8; 6]) -> Result<(), Error> {
    for (offset, value) in mac.iter().copied().enumerate() {
        byte(io, REG_MACID + offset as u16, value)?;
    }
    Ok(())
}
