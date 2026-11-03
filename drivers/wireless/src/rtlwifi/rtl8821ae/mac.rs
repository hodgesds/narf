// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE operational MAC while packet DMA is still parked.
//!
//! Linux `rtl8821ae/hw.c::_rtl8821ae_init_mac` (after the enable flow and
//! LLT, which `power`/`llt` own), `rtl8821ae_hw_init` and
//! `_rtl8821ae_hw_configure`. Deferred to the retained packet owner, exactly
//! where the EE runtime defers them: the `REG_CR = 0x2ff` DMA/MAC enable,
//! ring bases (`Prepared`), `REG_PCIE_CTRL_REG + 1 = 0` DMA release and
//! interrupt masks. Omitted with reason: `_rtl8821ae_gen_refresh_led_state`
//! (LED only), `_rtl8821ae_enable_aspm_back_door` (ASPM stays disabled by
//! probe; separate ASPM continuation) and hardware CAM crypto (the shared
//! software CCMP path is used, so `REG_SECR` stays 0 as for RTL8188EE).

use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// `sw.c` `receive_config`: APPFCS | APP_MIC | APP_ICV | APP_PHYST_RXFF |
/// NONQOS_VHT | HTC_LOC_CTRL | AMF | ACF | ADF | AICV | ACRC32 | AB | AM | APM.
pub const RCR: u32 = 0xf400_7b0e;
/// `REG_CR` word written by `_rtl8821ae_init_mac` once packet DMA may run.
pub const CR_RUNNING: u16 = 0x02ff;
/// `sw.c` `irq_mask[0]` (PSTIMEOUT|GTINT3|HSISR_IND_ON_INT|C2HCMD|HIGHDOK|
/// MGNTDOK|BKDOK|BEDOK|VIDOK|VODOK|RDU|ROK) and `irq_mask[1]` (RX/TXFOVW).
pub const IRQ_MASK: [u32; 2] = [0x2800_84ff, 0x0000_0300];
/// `sw.c` `sys_irq_mask` (`HSIMR_PDN_INT_EN | HSIMR_RON_INT_EN`).
pub const SYS_IRQ_MASK: u32 = 0xc0;
/// `WIFI_NAV_UPPER_US` rounded up to `HAL_92C_NAV_UPPER_UNIT` (128 us).
pub const NAV_UPPER: u8 = 235;

pub const REG_APS_FSMCO: u16 = 0x0004;
pub const REG_GPIO_MUXCFG: u16 = 0x0040;
pub const REG_HISR: u16 = 0x00b4;
pub const REG_HISRE: u16 = 0x00bc;
pub const REG_SYS_CFG: u16 = 0x00f0;
pub const REG_TRXDMA_CTRL: u16 = 0x010c;
pub const REG_FWIMR: u16 = 0x0130;
pub const REG_MCUTST_1: u16 = 0x01c0;
pub const REG_RXDMA_CONTROL: u16 = 0x0286;
pub const REG_PCIE_CTRL_REG: u16 = 0x0300;
pub const REG_INT_MIG: u16 = 0x0304;
pub const REG_FWHW_TXQ_CTRL: u16 = 0x0420;
pub const REG_HWSEQ_CTRL: u16 = 0x0423;
pub const REG_SECONDARY_CCA_CTRL: u16 = 0x0577;
pub const REG_RCR: u16 = 0x0608;
pub const REG_MACID: u16 = 0x0610;
pub const REG_NAV_UPPER: u16 = 0x0652;
pub const REG_SECR: u16 = 0x0680;
pub const REG_RXFLTMAP2: u16 = 0x06a4;

fn byte(io: &impl Io, reg: u16, value: u8) -> Result<(), Error> {
    io.write8(reg, value)?;
    if io.read8(reg)? != value {
        return Err(Error::Readback);
    }
    Ok(())
}
fn update8(io: &impl Io, reg: u16, set: u8, clear: u8) -> Result<(), Error> {
    byte(io, reg, (io.read8(reg)? & !clear) | set)
}
fn word(io: &impl Io, reg: u16, value: u16) -> Result<(), Error> {
    io.write16(reg, value)?;
    if u16::from_le_bytes([io.read8(reg)?, io.read8(reg + 1)?]) != value {
        return Err(Error::Readback);
    }
    Ok(())
}
fn w8(io: &impl Io, reg: u16, value: u8) -> Result<(), Error> {
    Ok(io.write8(reg, value)?)
}
fn w16(io: &impl Io, reg: u16, value: u16) -> Result<(), Error> {
    Ok(io.write16(reg, value)?)
}
fn w32(io: &impl Io, reg: u16, value: u32) -> Result<(), Error> {
    Ok(io.write32(reg, value)?)
}
fn dword(io: &impl Io, reg: u16, value: u32) -> Result<(), Error> {
    io.write32(reg, value)?;
    if io.read32(reg)? != value {
        return Err(Error::Readback);
    }
    Ok(())
}

/// `_rtl8821ae_init_mac` after the enable flow, with CR DMA/MAC gates and
/// ring bases left to the retained owner. `REG_CR = 0xff` and the final
/// `0x2ff` word are therefore not written here.
pub fn init_mac(io: &impl Io) -> Result<(), Error> {
    update8(io, REG_APS_FSMCO, 1 << 4, 0)?;
    byte(io, REG_HWSEQ_CTRL, 0xff)?;
    // RTL8821AE: REG_SYS_CFG + 3 BIT0 selects 0x7c BIT6.
    if io.read8(REG_SYS_CFG + 3)? & 1 != 0 {
        update8(io, 0x7c, 1 << 6, 0)?;
    }
    update8(io, REG_GPIO_MUXCFG + 1, 0, 1 << 4)?;
    // W1C status clear; not an acknowledgement of serviced work.
    io.write32(REG_HISR, u32::MAX)?;
    io.write32(REG_HISRE, u32::MAX)?;
    update8(io, REG_FWIMR + 3, 1 << 6, 0)?;
    let old = u16::from_le_bytes([io.read8(REG_TRXDMA_CTRL)?, io.read8(REG_TRXDMA_CTRL + 1)?]);
    word(io, REG_TRXDMA_CTRL, (old & 0xf) | 0xf5b1)?;
    byte(io, REG_FWHW_TXQ_CTRL + 1, 0x1f)?;
    dword(io, REG_RCR, RCR)?;
    word(io, REG_RXFLTMAP2, 0xffff)?;
    byte(io, REG_PCIE_CTRL_REG + 3, 0x77)?;
    dword(io, REG_INT_MIG, 0)?;
    dword(io, REG_MCUTST_1, 0)?;
    byte(io, REG_SECONDARY_CCA_CTRL, 0x3)
}

/// `_rtl8821ae_hw_configure`. Plain writes exactly as Linux: these rate,
/// aggregation and timing registers are not read back by the source.
pub fn hw_configure(io: &impl Io) -> Result<(), Error> {
    w32(io, 0x0440, 0x0fff)?; // REG_RRSR: RATE_ALL_CCK | RATE_ALL_OFDM_AG
    w32(io, 0x0444 + 4, 0xffff_f000)?; // ARFR0+4: 11ac 5G 2SS
    w32(io, 0x044c + 4, 0x003f_f000)?; // ARFR1+4: 11ac 5G 1SS
    w32(io, 0x048c, 0x0000_0015)?; // ARFR2: 11ac 2.4G 1SS
    w32(io, 0x048c + 4, 0x003f_f000)?;
    w32(io, 0x0494, 0x0000_0015)?; // ARFR3
    w32(io, 0x0494 + 4, 0xffcf_f000)?;
    w16(io, REG_FWHW_TXQ_CTRL, 0x1f00)?;
    w8(io, 0x0456, 0x70)?; // REG_AMPDU_MAX_TIME
    w16(io, 0x042a, 0x0707)?; // REG_RL
    w32(io, 0x0430, 0x0100_0000)?; // REG_DARFRC
    w32(io, 0x0434, 0x0706_0504)?;
    w32(io, 0x0438, 0x0100_0000)?; // REG_RARFRC
    w32(io, 0x043c, 0x0706_0504)?;
    w8(io, 0x0550, 0x1d)?; // REG_BCN_CTRL = reg_bcn_ctrl_val
    w8(io, 0x0541, 0xff)?; // REG_TBTT_PROHIBIT + 1
    w16(io, 0x0546, 0x0040)?; // REG_NAV_PROT_LEN
    w32(io, 0x0460, 0x0308_6666)?; // REG_FAST_EDCA_CTRL
    w8(io, 0x04c7, 0x80)?; // REG_HT_SINGLE_AMPDU
    w8(io, 0x060c, 0x20)?; // REG_RX_PKT_LIMIT
    w16(io, 0x04ca, 0x1f1f) // REG_MAX_AGGR_NUM
}

/// `rtl8821ae_hw_init` steps after `_rtl8821ae_hw_configure` that touch no
/// DMA gate: software crypto, `HW_VAR_ETHER_ADDR`, `HW_VAR_NAV_UPPER`, and
/// the conditional `REG_RXDMA_CONTROL` BIT2 release.
pub fn station_identity(io: &impl Io, mac: &[u8; 6]) -> Result<(), Error> {
    byte(io, REG_SECR, 0)?;
    for (offset, value) in mac.iter().copied().enumerate() {
        byte(io, REG_MACID + offset as u16, value)?;
    }
    byte(io, REG_NAV_UPPER, NAV_UPPER)?;
    let rxdma = io.read8(REG_RXDMA_CONTROL)?;
    if rxdma & (1 << 2) != 0 {
        byte(io, REG_RXDMA_CONTROL, rxdma & !(1 << 2))?;
    }
    Ok(())
}

/// Composed parked hardware initialization: init_mac remainder, MAC/BB/RF
/// tables, `_rtl8821ae_hw_configure` and the station identity.
pub async fn configure(
    io: &impl Io,
    condition: &super::headerfile::Condition,
    logical: &[u8],
    mac: &[u8; 6],
) -> Result<super::phy::Report, Error> {
    init_mac(io)?;
    let report = super::phy::configure(io, condition, logical).await?;
    hw_configure(io)?;
    station_identity(io, mac)?;
    Ok(report)
}
