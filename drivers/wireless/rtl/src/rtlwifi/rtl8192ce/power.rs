// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192CE / RTL8188CE power-on (the `_rtl92ce_init_mac` prefix).
//!
//! This family has no `rtl_hal_pwrseqcmdparsing` table: Linux
//! `rtl8192ce/hw.c::_rtl92ce_init_mac` powers the MAC with explicit writes
//! before `REG_CR = 0x2ff`, the LLT and the ring bases. [`power_on`] is that
//! prefix, for boards without BT coexistence (the `bt_coexistence` branches —
//! `REG_APS_FSMCO |= SOP_ABG|SOP_AMB|XOP_BTCK`, `REG_AFE_XTAL_CTRL &=
//! ~0x00024800`, `REG_AFE_XTAL_CTRL+2 &= 0xfd` — are not issued; such boards
//! are never admitted). `REG_CR = 0x2ff` opens every DMA/MAC engine and
//! belongs to the retained ring owner together with the LLT and ring bases.
//!
//! Linux keeps going when `APS_FSMCO+1` BIT0 (`APFM_ONMAC`) is still set
//! after its 1000 × 100 us poll; here that is a gate failure, so no later
//! step runs over a MAC that never reported power-on.

use crate::rtlwifi::firmware_transport::{Error, Io};

/// `reg.h`.
pub const REG_SYS_ISO_CTRL: u16 = 0x0000;
pub const REG_APS_FSMCO: u16 = 0x0004;
pub const REG_SPS0_CTRL: u16 = 0x0011;
pub const REG_RSV_CTRL: u16 = 0x001c;
pub const REG_AFE_XTAL_CTRL: u16 = 0x0024;

/// `_rtl92ce_init_mac` `while ((bytetmp & BIT(0)) && retry < 1000)`.
const APFM_RETRIES: u32 = 1000;

/// The `_rtl92ce_init_mac` power-on prefix (non-BT boards), up to but not
/// including `REG_CR = 0x2ff`.
pub async fn power_on<I: Io + ?Sized>(io: &I) -> Result<(), Error> {
    io.write8(REG_RSV_CTRL, 0x00)?;
    io.write8(REG_SPS0_CTRL, 0x2b)?;
    io.write8(REG_AFE_XTAL_CTRL, 0x0f)?;
    let value = io.read8(REG_APS_FSMCO + 1)? | 1;
    io.delay_us(2).await;
    io.write8(REG_APS_FSMCO + 1, value)?;
    io.delay_us(2).await;
    let mut value = io.read8(REG_APS_FSMCO + 1)?;
    io.delay_us(2).await;
    let mut retry = 0;
    while value & 1 != 0 && retry < APFM_RETRIES {
        retry += 1;
        io.delay_us(50).await;
        value = io.read8(REG_APS_FSMCO + 1)?;
        io.delay_us(50).await;
    }
    if value & 1 != 0 {
        return Err(Error::Gate);
    }
    io.write16(REG_APS_FSMCO, 0x1012)?;
    io.write8(REG_SYS_ISO_CTRL + 1, 0x82)?;
    io.delay_us(2).await;
    Ok(())
}
