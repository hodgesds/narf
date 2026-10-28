// SPDX-License-Identifier: GPL-2.0-or-later
//! Device reset and the dead-firmware stop proof.
//!
//! Linux v7.2 `pcie.c::brcmf_pcie_reset_device` (called by
//! `brcmf_pcie_remove` and `brcmf_pcie_reset` after the IRQ and ring
//! release): clear ASPM in `BRCMF_PCIE_REG_LINK_STATUS_CTRL`, write 4 to
//! the ChipCommon `watchdog` register, sleep 100 ms, restore the link
//! control word and, on PCIe2 core revision <= 13, rewrite the eleven
//! `BRCMF_PCIE_CFGREG_*` config words from the core's
//! `CONFIGADDR`/`CONFIGDATA` shadow.
//!
//! When firmware halted (`BRCMF_D2H_DEV_FWHALT`, Linux `brcmf_fw_crashed`)
//! or lost power across suspend (`brcmf_pcie_pm_leave_D3` reads a zero
//! `INTMASK`), no D3 ack can arrive, so the confirmed stop of `quiesce.rs`
//! cannot run. The dead stop instead releases the IRQ, clears BME with a
//! verified readback, issues non-posted flush reads (their completions
//! order behind every posted write the function issued before the clear)
//! that must observe a present function and stable D2H write indices,
//! resets the chip by the ChipCommon watchdog, re-verifies BME clear after
//! the config shadow restore, halts the ARM CR4 (`brcmf_chip_set_passive`)
//! and reads the halt back. Only then is the published memory reclaimable.
use super::*;
use crate::brcmfmac::chip::{self, Chip};

/// ChipCommon `watchdog` register (`struct chipcregs`, offset 0x80).
const CC_WATCHDOG: u32 = 0x80;
/// `BRCMF_PCIE_LINK_STATUS_CTRL_ASPM_ENAB`.
const ASPM_ENAB: u32 = 3;
/// `BRCMF_PCIE_PCIE2REG_CONFIGADDR` / `CONFIGDATA`.
const PCIE2_CONFIGADDR: u32 = 0x120;
const PCIE2_CONFIGDATA: u32 = 0x124;
/// `brcmf_pcie_reset_device` `cfg_offset[]`.
const SHADOWED: [u32; 11] = [
    0x4, 0x4c, 0x58, 0x5c, 0x60, 0x64, 0xdc, 0x228, 0x248, 0x4e0, 0x4f4,
];
/// `ARMCR4_BCMA_IOCTL_CPUHALT`.
const CPUHALT: u32 = 0x20;
/// AI wrapper `ioctrl` / `resetctrl`.
const AI_IOCTRL: u32 = 0x408;
const AI_RESETCTRL: u32 = 0x800;
/// `msleep(100)` after the watchdog write.
const WATCHDOG_SETTLE_MS: u64 = 100;

/// Outcome of a dead-firmware stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeadStop {
    /// D2H write indices observed by both post-BME flush reads.
    pub indices: [u16; 3],
    /// ARM CR4 wrapper `ioctrl` read back after the halt.
    pub halted: u32,
}

impl<B: Bus> Runtime<B> {
    fn core_of(&self, id: u16) -> Result<chip::Core, Error> {
        self.cores
            .iter()
            .copied()
            .find(|core| core.id == id)
            .ok_or(Error::Protocol)
    }
    fn backplane_read(&mut self, address: u32) -> Result<u32, Error> {
        match self.bus.read32(address) {
            Ok(u32::MAX) | Err(_) => Err(Error::Access),
            Ok(value) => Ok(value),
        }
    }
    fn backplane_write(&mut self, address: u32, value: u32) -> Result<(), Error> {
        self.bus.write32(address, value).map_err(|_| Error::Access)
    }
    /// `brcmf_pcie_reset_device`, followed by a verified BME clear and a
    /// halted ARM CR4 (`brcmf_chip_set_passive`: CR4 reset with
    /// `CPUHALT`, D11 cores disabled) read back from its wrapper. The
    /// caller must have released the IRQ and cleared BME.
    pub async fn reset_device(&mut self) -> Result<u32, Error> {
        let common = self.core_of(chip::CORE_CHIPCOMMON)?;
        let pcie = self.core_of(chip::CORE_PCIE2)?;
        let arm = self.core_of(chip::CORE_ARM_CR4)?;
        let lsc = self.bus.link_control()?;
        self.bus.set_link_control(lsc & !ASPM_ENAB)?;
        self.backplane_write(common.base + CC_WATCHDOG, 4)?;
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            WATCHDOG_SETTLE_MS * 1_000_000,
        ))
        .await;
        self.bus.set_link_control(lsc)?;
        if pcie.revision <= 13 {
            for offset in SHADOWED {
                self.backplane_write(pcie.base + PCIE2_CONFIGADDR, offset)?;
                let value = self
                    .bus
                    .read32(pcie.base + PCIE2_CONFIGDATA)
                    .map_err(|_| Error::Access)?;
                self.backplane_write(pcie.base + PCIE2_CONFIGDATA, value)?;
            }
        }
        // The shadow restore rewrote STATUS_CMD: BME must still read clear.
        if self.bus.dma_enabled()? {
            self.bus.park_dma()?;
            if self.bus.dma_enabled()? {
                return Err(Error::Access);
            }
        }
        Chip::reset_core(&mut self.bus, arm, CPUHALT, CPUHALT, CPUHALT)
            .map_err(|_| Error::Access)?;
        let d11: Vec<chip::Core> = self
            .cores
            .iter()
            .copied()
            .filter(|core| core.id == chip::CORE_D11)
            .collect();
        for core in d11 {
            Chip::disable_core(&mut self.bus, core, 12, 4).map_err(|_| Error::Access)?;
        }
        let ioctrl = self.backplane_read(arm.wrapper + AI_IOCTRL)?;
        let resetctrl = self.backplane_read(arm.wrapper + AI_RESETCTRL)?;
        if ioctrl & CPUHALT == 0 || resetctrl & 1 != 0 {
            return Err(Error::Protocol);
        }
        Ok(ioctrl)
    }
    /// Stop a generation whose firmware cannot acknowledge D3 (FWHALT,
    /// lost power, a timed-out or terminal owner). On success all
    /// published memory is reclaimable; any failure keeps it pinned.
    pub async fn stop_dead(&mut self) -> Result<DeadStop, Error> {
        if self.reclaimable {
            return Err(Error::Busy);
        }
        // BRCMFMAC_PCIE_STATE_DOWN: this generation never posts again.
        self.down = true;
        self.failed = true;
        if let Some(mailbox) = self.mailbox.as_mut() {
            mailbox.awaiting = false;
        }
        self.stop_interrupts();
        self.bus.park_dma()?;
        if self.bus.dma_enabled()? {
            return Err(Error::Access);
        }
        let mailbox = self.mailbox.ok_or(Error::Protocol)?;
        let first = self.completion_indices()?;
        self.read_reg(mailbox.reg.mailboxint)?;
        let second = self.completion_indices()?;
        if first != second {
            return Err(Error::Protocol);
        }
        let halted = self.reset_device().await?;
        self.reclaimable = true;
        Ok(DeadStop {
            indices: second,
            halted,
        })
    }
}
