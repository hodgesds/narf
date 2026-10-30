// SPDX-License-Identifier: GPL-2.0-or-later
//! Park an old generation before fresh-ROM recovery. After every CE halted
//! and bus mastering reads back clear, an ordered flush read (no Relaxed
//! Ordering) lets the retired owner free its allocations on Drop; any failed
//! step keeps them pinned. No RF-quiescence claim is made.
use super::*;

pub(in crate::ath10k) struct Restart {
    pub device: BusDevice,
    pub cap: Cap<BusDeviceCap, Write>,
    pub mmio: MmioRegion,
    pub hardware: HwRev,
    /// The retired owner proved quiescence and frees its DMA on Drop.
    pub reclaimable: bool,
}

fn park(
    mmio: &mut impl Ath10kMmio,
    hardware: HwRev,
    mut disable_master: impl FnMut() -> Result<(), BmiError>,
) -> Result<(), BmiError> {
    let regs = hardware.registers().ok_or(BmiError::Unsupported)?;
    if !mmio.authorized() {
        return Err(BmiError::Pci);
    }
    mmio.write32(regs.soc_core + 8, 0);
    let mut halted = true;
    for pipe in 0..regs.ce_count {
        let base = regs.ce_base(pipe).ok_or(BmiError::Unsupported)?;
        mmio.write32(base + hw::ce_off::HOST_IE, 0);
        mmio.write32(base + hw::ce_off::MISC_IE, 0);
        halted &= ce::halt_pipe(mmio, hardware, pipe).is_ok();
    }
    // Attempt bus-master disable even if one engine refuses to halt.
    disable_master()?;
    if !mmio.authorized() {
        return Err(BmiError::Pci);
    }
    barrier();
    if !halted {
        return Err(BmiError::Timeout);
    }
    Ok(())
}

/// Reset only to ROM; do not install queues, load executable code or enable
/// bus mastering. QCA988X/9887 use the safe CPU warm reset; the other supported
/// families use the same SoC cold-reset pulse as their fresh-ROM power-up.
async fn reset_to_rom(mmio: &mut impl Ath10kMmio, hardware: HwRev) -> Result<(), BmiError> {
    let regs = hardware.registers().ok_or(BmiError::Unsupported)?;
    if !mmio.authorized() {
        return Err(BmiError::Pci);
    }
    if matches!(hardware, HwRev::Qca988x | HwRev::Qca9887) {
        // Linux ath10k_pci_warm_reset_si0 clears the memory-controller
        // assert line before resetting the target CPU. Preserve the safe
        // warm-reset family; never use its problematic cold-reset fallback.
        let value = mmio.read32(regs.rtc_soc);
        if value == u32::MAX {
            return Err(BmiError::DeviceGone);
        }
        mmio.write32(regs.rtc_soc, value | 1);
        let _ = mmio.read32(regs.rtc_soc);
        PciBoot::delay(10).await;
        let value = mmio.read32(regs.rtc_soc);
        if value == u32::MAX {
            return Err(BmiError::DeviceGone);
        }
        mmio.write32(regs.rtc_soc, value & !1);
        let _ = mmio.read32(regs.rtc_soc);
        PciBoot::delay(10).await;
        mmio.write32(regs.fw_indicator, 0);
        let value = mmio.read32(regs.rtc_soc);
        if value == u32::MAX {
            return Err(BmiError::DeviceGone);
        }
        mmio.write32(regs.rtc_soc, value | 0x40);
        PciBoot::delay(10).await;
    } else {
        mmio.write32(regs.fw_indicator, 0);
        let address = regs.pcie_local + 8;
        let value = mmio.read32(address);
        if value == u32::MAX {
            return Err(BmiError::DeviceGone);
        }
        mmio.write32(address, value | 1);
        // No PCIe register access while the link is settling.
        PciBoot::delay(20).await;
        mmio.write32(address, value & !1);
        PciBoot::delay(20).await;
    }
    if !mmio.authorized() {
        return Err(BmiError::Pci);
    }
    barrier();
    Ok(())
}

/// An ambiguous halt cannot bypass reset or the post-reset BME-off attempt.
/// `true` is only the original CE halt proof; reset never invents that proof.
async fn silence(
    mmio: &mut impl Ath10kMmio,
    hardware: HwRev,
    mut disable_master: impl FnMut() -> Result<(), BmiError>,
) -> Result<bool, BmiError> {
    hardware.registers().ok_or(BmiError::Unsupported)?;
    let parked = park(mmio, hardware, &mut disable_master);
    let reset = reset_to_rom(mmio, hardware).await;
    let disabled = disable_master();
    disabled?;
    reset?;
    Ok(parked.is_ok())
}

impl PciBoot {
    fn retire_scope(&mut self) -> Result<Cap<BusDeviceCap, Write>, BmiError> {
        if self.retired {
            return Err(BmiError::BadResponse);
        }
        // Terminal before detaching an expired executable/board scope. Only
        // current PCI invocation is needed to silence hardware; this never
        // authorizes BMI/WMI or reuses the revoked mission image.
        self.retired = true;
        self.poisoned = true;
        self.hif_live = false;
        self.power_ready = false;
        self.mmio.sources = None;
        let cap = self.mmio.cap.derive::<Write>().map_err(|_| BmiError::Pci)?;
        self.stop_interrupts();
        Ok(cap)
    }

    pub(in crate::ath10k) async fn retire_after_failed_scan(
        &mut self,
    ) -> Result<Restart, BmiError> {
        let cap = self.retire_scope()?;
        let device = self.device;
        let halted = silence(&mut self.mmio, self.hardware, || {
            crate::qualcomm_pci::invoke(&cap, || {
                narf_bus::pci::clear_command(&cap, &device, narf_bus::pci::cmd::BUS_MASTER)
                    .map_err(|_| BmiError::Pci)?;
                let command =
                    narf_bus::pci::read_command(&cap, &device).map_err(|_| BmiError::Pci)?;
                if command & narf_bus::pci::cmd::BUS_MASTER != 0 {
                    return Err(BmiError::Pci);
                }
                Ok(())
            })
            .map_err(|_| BmiError::Pci)?
        })
        .await?;
        self.reclaimable = halted && self.flushed();
        Ok(Restart {
            device,
            cap,
            mmio: self.mmio.io.0,
            hardware: self.hardware,
            reclaimable: self.reclaimable,
        })
    }

    pub(in crate::ath10k) fn retire_for_restart(&mut self) -> Result<Restart, BmiError> {
        let cap = self.retire_scope()?;
        let device = self.device;
        park(&mut self.mmio, self.hardware, || {
            crate::qualcomm_pci::invoke(&cap, || {
                narf_bus::pci::clear_command(&cap, &device, narf_bus::pci::cmd::BUS_MASTER)
                    .map_err(|_| BmiError::Pci)?;
                let command =
                    narf_bus::pci::read_command(&cap, &device).map_err(|_| BmiError::Pci)?;
                if command & narf_bus::pci::cmd::BUS_MASTER != 0 {
                    return Err(BmiError::Pci);
                }
                Ok(())
            })
            .map_err(|_| BmiError::Pci)?
        })?;
        self.reclaimable = self.flushed();
        Ok(Restart {
            device,
            cap,
            mmio: self.mmio.io.0,
            hardware: self.hardware,
            reclaimable: self.reclaimable,
        })
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "recovery_tests.rs"]
mod tests;
