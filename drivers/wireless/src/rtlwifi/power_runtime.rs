// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8188EE / RTL8821AE card-disable/enable sequencing for a retained
//! reset owner.
//!
//! Linux rtl8188ee/hw.c::_rtl88ee_poweroff_adapter and pwrseq.h;
//! rtl8821ae/hw.c::_rtl8821ae_poweroff_adapter / _rtl8821ae_init_mac and
//! pwrseq.c. This transition is driven by the retained native recovery owner.
//! Callers must retain exclusive current PCI ownership, park bus mastering,
//! withdraw interrupts and prove the old packet DMA idle before these flows.
//! No operation here enables PCI bus mastering or releases a DMA allocation.
use super::{
    firmware_transport::{Error, Io},
    power::*,
};
use narf_time::Deadline;

async fn update(io: &impl Io, at: u16, clear: u8, set: u8) -> Result<(), Error> {
    let value = io.read8(at)?;
    io.write8(at, (value & !clear) | set)
}

async fn poll(io: &impl Io, at: u16, mask: u8, expected: u8) -> Result<(), Error> {
    let deadline = Deadline::after_ms(100);
    loop {
        if io.read8(at)? & mask == expected & mask {
            return Ok(());
        }
        if deadline.expired() {
            return Err(Error::Deadline);
        }
        io.delay_us(10).await;
    }
}

/// The existing source-backed power table, driven cooperatively. Each native
/// register operation remains inside PciIo's current capability invocation.
/// `cut` is the `rtl_hal_pwrseqcmdparsing` cut-version mask of the caller.
async fn flow(io: &impl Io, cut: u8, table: &[WlanPwrCfg]) -> Result<(), Error> {
    for row in table {
        if row.intf() & PWR_INTF_PCI_MSK == 0
            || row.cut_msk & cut == 0
            || row.fab() & PWR_FAB_ALL_MSK == 0
        {
            continue;
        }
        if row.cmd() == PWR_CMD_END {
            return Ok(());
        }
        if row.base() != PWR_BASEADDR_MAC {
            return Err(Error::Unsupported);
        }
        match row.cmd() {
            PWR_CMD_READ => {
                io.read8(row.offset)?;
            }
            PWR_CMD_WRITE => {
                update(io, row.offset, row.msk, row.value & row.msk).await?;
            }
            PWR_CMD_POLLING => poll(io, row.offset, row.msk, row.value).await?,
            PWR_CMD_DELAY => {
                let us = match row.value {
                    PWRSEQ_DELAY_US => u64::from(row.offset),
                    PWRSEQ_DELAY_MS => u64::from(row.offset) * 1000,
                    _ => return Err(Error::Unsupported),
                };
                io.delay_us(us).await;
            }
            _ => return Err(Error::Unsupported),
        }
    }
    Err(Error::Unsupported)
}

/// Restore CardDisabled/CardEmu to Active before the fresh firmware download,
/// LLT, radio IQ/LC and packet-ring initialization. Uses the same qualified
/// RTL8188EE table as initial probe, including the card-enable prefix.
pub(super) async fn enable(io: &impl Io) -> Result<(), Error> {
    update(io, 0x7c, 1, 0).await?;
    update(io, 5, 0x80, 0).await?;
    io.write8(0x1c, 0)?;
    flow(io, PWR_CUT_ALL_MSK, RTL8188EE_PWR_ON).await
}

/// Stop the firmware CPU and execute ACT→LPS→CardEmu→CardDisabled after
/// the independent old-DMA retirement proof. Firmware self-reset is the
/// source's SYS_FUNC_EN+1 bit2 pulse, followed by its final disabled state.
/// A cancelled future leaves the logical owner closed and the bus parked;
/// no firmware-ready or quiescence receipt is inferred from submission.
pub(super) async fn disable(io: &impl Io, firmware_ready: bool) -> Result<(), Error> {
    update(io, 0x4ec, 2, 0).await?; // TX report timer off.
    poll(io, 0x286, 2, 2).await?; // RXDMA_IDLE, not a loop-count proof.
    io.write8(0x301, 0xff)?; // Stop host TX DMA.

    // RTL8188EE_TRANS_ACT_TO_LPS (PCI rows), in source order.
    io.write8(0x522, 0x7f)?;
    for reg in 0x5f8..=0x5fb {
        poll(io, reg, 0xff, 0).await?;
    }
    update(io, 2, 1, 0).await?;
    io.delay_us(2).await; // Native table's PWR_CMD_DELAY offset is 0x0002.
    io.write8(0x100, 0x3f)?;
    update(io, 0x101, 2, 0).await?;
    update(io, 0x553, 0, 0x20).await?;
    io.write8(0x1f, 0)?; // RF off.

    if io.read8(0x80)? & 0x80 != 0 && firmware_ready {
        let function = io.read8(3)?;
        io.write8(3, function & !4)?;
        io.write8(3, function | 4)?;
    }
    update(io, 3, 4, 0).await?;
    io.write8(0x80, 0)?;
    update(io, 0x194, 1, 0).await?;

    // NIC_DISABLE_FLOW: ACT→CardEmu, then PCI CardEmu→CardDisabled.
    io.write8(0x1f, 0)?;
    update(io, 0x23, 0, 0x10).await?;
    update(io, 5, 0, 2).await?;
    poll(io, 5, 2, 0).await?;
    update(io, 0x26, 0, 0x80).await?;

    update(io, 0x1d, 8, 0).await?;
    update(io, 0x1d, 0, 8).await?;
    io.write8(0x1c, 0x0e)?;
    io.write8(0x45, io.read8(0x44)?)?;
    io.write8(0x46, 0x7f)?;
    let gpio = io.read8(0x42)?;
    io.write8(0x42, (gpio << 4) | gpio)?;
    update(io, 0x43, 0, 0x0f).await?;
    io.write32(0x64, 0x0008_0808)?;
    Ok(())
}

/// RTL8821AE CardDisabled→Active before the fresh firmware download:
/// `_rtl8821ae_init_mac` unlocks REG_RSV_CTRL (0x1c = 0), clears
/// APS_FSMCO+1 BIT(7) (auto power-down) and parses
/// `RTL8821A_NIC_ENABLE_FLOW` with `PWR_CUT_A_MSK` — the same entry the
/// initial probe runs synchronously through `power::power_on_with`.
pub(super) async fn enable_rtl8821ae(io: &impl Io) -> Result<(), Error> {
    io.write8(0x1c, 0)?;
    update(io, 5, 0x80, 0).await?;
    flow(
        io,
        PWR_CUT_A_MSK,
        super::rtl8821ae::pwrseq::RTL8821A_CARD_ENABLE_FLOW,
    )
    .await
}

/// RTL8192EE CardDisabled→Active before the fresh firmware download: the
/// `rtl8192ee/hw.c::_rtl92ee_init_mac` prefix (REG_RSV_CTRL = 0,
/// `REG_SYS_CFG1[24]` ⇒ `0x7c = 0xc3` else `0x16 |= BIT4|BIT6` and `0x7c =
/// 0x83`, `REG_AFE_CTRL2 &= 0xfb`, `REG_AFE_CTRL4 &= 0xfffffc7f`,
/// `REG_AFE_CTRL2 &= 0xbf`, `REG_AFE_CTRL4 &= 0xffdfffff` as byte RMWs),
/// then `RTL8192E_NIC_ENABLE_FLOW` — the same entry the initial probe runs
/// synchronously through `power::power_on_with`.
pub(super) async fn enable_rtl8192ee(io: &impl Io) -> Result<(), Error> {
    io.write8(0x1c, 0)?;
    if io.read8(0xf0 + 3)? & 1 != 0 {
        io.write8(0x7c, 0xc3)?;
    } else {
        update(io, 0x16, 0, (1 << 4) | (1 << 6)).await?;
        io.write8(0x7c, 0x83)?;
    }
    update(io, 0x28, 0x04, 0).await?;
    update(io, 0x78, 0x80, 0).await?;
    update(io, 0x79, 0x03, 0).await?;
    update(io, 0x28, 0x40, 0).await?;
    update(io, 0x7a, 0x20, 0).await?;
    flow(io, PWR_CUT_ALL_MSK, RTL8192EE_PWR_ON).await
}

/// RTL8821AE `_rtl8821ae_poweroff_adapter` (the `rtl8821ae_card_disable`
/// normal power-off branch), in source order, after the independent
/// old-DMA retirement proof:
/// `RTL8821A_NIC_LPS_ENTER_FLOW` (stops PCI TX DMA, pauses TX, polls the
/// 0x5f8..0x5fb queues empty, resets BB, CR = 0x03, CR+1 BIT1 off,
/// 0x553 BIT5); `rtl8821ae_firmware_selfreset` when MCUFWDL BIT(7) and the
/// firmware is ready; SYS_FUNC_EN+1 BIT(2) off (MCU reset); MCUFWDL = 0;
/// `RTL8821A_NIC_DISABLE_FLOW`; the REG_RSV_CTRL+1 BIT(0) MCU IO-wrapper
/// reset pulse; REG_RSV_CTRL = 0x0e. Linux first calls
/// `_rtl8821ae_set_media_status(UNSPECIFIED)`; that MSR write is not
/// issued here (as on 88EE): the card-disable/enable cycle resets MSR and
/// the fresh owner's MAC init reprograms it before any link exists.
/// A cancelled future leaves the logical owner closed and the bus parked.
pub(super) async fn disable_rtl8821ae(io: &impl Io, firmware_ready: bool) -> Result<(), Error> {
    use super::rtl8821ae::pwrseq::{RTL8821A_CARD_DISABLE_FLOW, RTL8821A_ENTER_LPS_FLOW};
    flow(io, PWR_CUT_ALL_MSK, RTL8821A_ENTER_LPS_FLOW).await?;
    if io.read8(0x80)? & 0x80 != 0 && firmware_ready {
        // fw.c::rtl8821ae_firmware_selfreset (non-8812 branch).
        update(io, 0x1d, 1, 0).await?;
        update(io, 3, 4, 0).await?;
        io.delay_us(50).await;
        update(io, 0x1d, 0, 1).await?;
        update(io, 3, 0, 4).await?;
    }
    update(io, 3, 4, 0).await?;
    io.write8(0x80, 0)?;
    flow(io, PWR_CUT_ALL_MSK, RTL8821A_CARD_DISABLE_FLOW).await?;
    update(io, 0x1d, 1, 0).await?;
    update(io, 0x1d, 0, 1).await?;
    io.write8(0x1c, 0x0e)
}

/// RTL8192EE `rtl92ee_card_disable` → `_rtl92ee_poweroff_adapter`, in
/// source order, after the independent old-DMA retirement proof
/// (`Prepared::quiesce`): `RTL8192E_NIC_LPS_ENTER_FLOW` (PCIe DMA stop, TX
/// pause, the 0x5f8..0x5fb TX-buffer polls, CCK/OFDM and BB reset, CR =
/// 0x03, CR+1 BIT1 off, 0x553 BIT5); `REG_RF_CTRL = 0` (8192EE-specific);
/// `rtl92ee_firmware_selfreset` when MCUFWDL BIT(7) and the firmware is
/// ready; SYS_FUNC_EN+1 BIT(2) off (MCU reset); MCUFWDL = 0;
/// `RTL8192E_NIC_DISABLE_FLOW`; the REG_RSV_CTRL+1 BIT(0) MCU IO-wrapper
/// reset pulse; REG_RSV_CTRL = 0x0e. Linux first calls
/// `_rtl92ee_set_media_status(UNSPECIFIED)`; that MSR write is not issued
/// (88EE/8821AE precedent: the card-disable/enable cycle resets MSR and the
/// fresh owner's MAC init reprograms it). LED control is not composed.
pub(super) async fn disable_rtl8192ee(io: &impl Io, firmware_ready: bool) -> Result<(), Error> {
    use super::rtl8192ee::pwrseq::{RTL8192E_CARD_DISABLE_FLOW, RTL8192E_ENTER_LPS_FLOW};
    flow(io, PWR_CUT_ALL_MSK, RTL8192E_ENTER_LPS_FLOW).await?;
    io.write8(0x1f, 0)?;
    if io.read8(0x80)? & 0x80 != 0 && firmware_ready {
        // fw.c::rtl92ee_firmware_selfreset.
        update(io, 0x1d, 1, 0).await?;
        update(io, 3, 4, 0).await?;
        io.delay_us(50).await;
        update(io, 0x1d, 0, 1).await?;
        update(io, 3, 0, 4).await?;
    }
    update(io, 3, 4, 0).await?;
    io.write8(0x80, 0)?;
    flow(io, PWR_CUT_ALL_MSK, RTL8192E_CARD_DISABLE_FLOW).await?;
    update(io, 0x1d, 1, 0).await?;
    update(io, 0x1d, 0, 1).await?;
    io.write8(0x1c, 0x0e)
}

/// RTL8723BE CardDisabled→Active before the fresh firmware download: the
/// `rtl8723be/hw.c::_rtl8723be_init_mac` prefix (`REG_RSV_CTRL = 0`,
/// `REG_APS_FSMCO + 1` BIT(7) cleared) and `RTL8723_NIC_ENABLE_FLOW` — the
/// same entry the initial probe runs synchronously through
/// `power::power_on_with`. The rest of `_rtl8723be_init_mac` (the
/// coexistence power-on setting, `REG_CR`, LLT, rings) is the fresh
/// owner's `prepare`.
pub(super) async fn enable_rtl8723be(io: &impl Io) -> Result<(), Error> {
    io.write8(0x1c, 0)?;
    update(io, 5, 0x80, 0).await?;
    flow(
        io,
        PWR_CUT_ALL_MSK,
        super::rtl8723be::pwrseq::RTL8723B_CARD_ENABLE_FLOW,
    )
    .await
}

/// RTL8723BE `rtl8723be_card_disable` → `_rtl8723be_poweroff_adapter`, in
/// source order, after the independent old-DMA retirement proof:
/// `RTL8723_NIC_LPS_ENTER_FLOW` (`rtl8723B_enter_lps_flow`); the `REG_RF_CTRL`
/// write is commented out in Linux and not issued;
/// `rtl8723be_firmware_selfreset` when MCUFWDL BIT(7) and the firmware is
/// ready; SYS_FUNC_EN+1 BIT(2) off (MCU reset); MCUFWDL = 0;
/// `RTL8723_NIC_DISABLE_FLOW` (`rtl8723B_card_disable_flow`); the
/// REG_RSV_CTRL+1 BIT(0) MCU IO-wrapper reset pulse; REG_RSV_CTRL = 0x0e.
/// Linux first calls `_rtl8723be_set_media_status(UNSPECIFIED)`; that MSR
/// write is not issued (88EE/8821AE/8192EE precedent). `iqk_initialized`
/// is kept: `get_btc_status()` is always true on this chip. LED control is
/// not composed. The rebuild owner composes it with the chip's admission.
pub(super) async fn disable_rtl8723be(io: &impl Io, firmware_ready: bool) -> Result<(), Error> {
    use super::rtl8723be::{
        fw,
        pwrseq::{RTL8723B_CARD_DISABLE_FLOW, RTL8723B_ENTER_LPS_FLOW},
    };
    flow(io, PWR_CUT_ALL_MSK, RTL8723B_ENTER_LPS_FLOW).await?;
    if io.read8(0x80)? & 0x80 != 0 && firmware_ready {
        fw::selfreset(io).await?;
    }
    update(io, 3, 4, 0).await?;
    io.write8(0x80, 0)?;
    flow(io, PWR_CUT_ALL_MSK, RTL8723B_CARD_DISABLE_FLOW).await?;
    update(io, 0x1d, 1, 0).await?;
    update(io, 0x1d, 0, 1).await?;
    io.write8(0x1c, 0x0e)
}

/// RTL8192CE / RTL8188CE `rtl92ce_card_disable` for the rebuild's power
/// down. The retained owner's quiescence (`ce92_quiesce`) already ran
/// `_rtl92ce_poweroff_adapter` after its descriptor retirement proof and
/// read back `REG_SYS_FUNC_EN + 1 == 0x51` (`FEN_DCORE` dropped); that
/// state is accepted unchanged, as Linux disables the card once. A card
/// still enabled (no owner was retained) runs the non-BT
/// `_rtl92ce_poweroff_adapter` for the live qualified version. There is no
/// matching enable step: the fresh owner's firmware run issues the
/// `_rtl92ce_init_mac` power prefix (`rtl8192ce::power::power_on`) before
/// the download, exactly once, as `rtl92ce_hw_init` does.
pub(super) async fn disable_rtl8192ce(io: &impl Io) -> Result<(), Error> {
    use super::rtl8192ce::{fw::REG_SYS_FUNC_EN, ps, version};
    if io.read8(REG_SYS_FUNC_EN + 1)? == 0x51 {
        return Ok(());
    }
    let sys_cfg = io.read32(version::REG_SYS_CFG)?;
    if sys_cfg == u32::MAX {
        return Err(Error::Gone);
    }
    let mut hpon = Ok(0);
    let qualified = version::Version::from_registers(sys_cfg, || {
        hpon = io.read32(version::REG_HPON_FSM);
        *hpon.as_ref().unwrap_or(&0)
    });
    hpon?;
    let qualified = qualified.map_err(|_| Error::Unsupported)?;
    ps::poweroff_adapter(io, qualified)
        .await
        .map_err(|error| match error {
            super::prepare::Error::Access(access) => access,
            _ => Error::Gate,
        })?;
    if io.read8(REG_SYS_FUNC_EN + 1)? != 0x51 {
        return Err(Error::Gate);
    }
    Ok(())
}
