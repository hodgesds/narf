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

impl PciBoot {
    pub(in crate::ath10k) fn retire_for_restart(&mut self) -> Result<Restart, BmiError> {
        if self.retired {
            return Err(BmiError::BadResponse);
        }
        let cap = self.mmio.cap.derive::<Write>().map_err(|_| BmiError::Pci)?;
        // ath10k_pci_hif_stop: mask CE/line/firmware sources and release the
        // vector before the generation becomes terminal.
        self.stop_interrupts();
        // Terminal before the first register operation. In particular, a late
        // Drop must never disable a successor's bus mastering or CE rings.
        self.retired = true;
        self.poisoned = true;
        self.hif_live = false;
        self.power_ready = false;
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
        })
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "recovery_tests.rs"]
mod tests;
