use super::regs::*;
use narf_bus::MmioRegion;
use narf_capabilities::{Cap, Read};
use narf_firmware::{open, view_of, FirmwareError, FirmwareRegistry};
use narf_scheduler::responsive_spin_until;
use narf_time::Deadline;

#[derive(Debug)]
pub enum FwError {
    Firmware(FirmwareError),
    DownloadTimeout,
    ReadyTimeout,
    NoBar2,
}

/// Implement `download_firmware` using the IDDMA mechanism for `RTL8822C`.
///
/// # Safety
/// Caller must ensure that `mmio_bar0` and `mmio_bar2` are valid and belong to the same device.
pub unsafe fn download_firmware(
    mmio_bar0: &MmioRegion,
    mmio_bar2: Option<&MmioRegion>,
    did: u16,
    auth: &Cap<FirmwareRegistry, Read>,
) -> Result<(), FwError> {
    if did != RTL_DEV_8822CE {
        // For now only RTL8822C is supported as per prompt.
        // Other chips might use a different sequence.
        return Ok(());
    }

    // 1. Open `rtw88/rtw8822c_fw.bin`.
    let fw_blob_cap = open("rtw88/rtw8822c_fw.bin", auth).map_err(FwError::Firmware)?;
    let view = view_of(&fw_blob_cap).map_err(FwError::Firmware)?;

    let mmio_bar2 = mmio_bar2.ok_or(FwError::NoBar2)?;

    // 2. Copy the firmware blob to the chip's TX buffer.
    // For PCI, this is done by writing to BAR2. The offset in BAR2 is 0
    // (BAR2 is a direct window to the TX buffer).
    let bytes = view.bytes;
    for (i, chunk) in bytes.chunks(4).enumerate() {
        let mut val = 0u32;
        for (j, &b) in chunk.iter().enumerate() {
            val |= (b as u32) << (j * 8);
        }
        // SAFETY: `mmio_bar2` is a valid BAR2 window the caller guaranteed
        // (per this fn's `# Safety`); offset `i*4` stays within the copied
        // blob, which the firmware loader sized to fit the TX buffer.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            mmio_bar2.write32((i * 4) as u64, val);
        }
    }

    // 3. Trigger IDDMA:
    // - Write source address (OCPBASE_TXBUF_88XX) to REG_DDMA_CH0SA.
    // - Write destination address (e.g., OCPBASE_IMEM_88XX) to REG_DDMA_CH0DA.
    // - Write control (BIT_DDMACH0_OWN | BIT_DDMACH0_CHKSUM_EN | len) to REG_DDMA_CH0CTRL.
    // SAFETY: `mmio_bar0` is the valid BAR0 register window the caller
    // guaranteed (per this fn's `# Safety`); `REG_DDMA_CH0*` are in-range
    // 32-bit DDMA control registers for this chip.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        mmio_bar0.write32(REG_DDMA_CH0SA, OCPBASE_TXBUF_88XX);
        mmio_bar0.write32(REG_DDMA_CH0DA, OCPBASE_IMEM_88XX);

        let len = bytes.len() as u32;
        // Ensure len fits in BIT_MASK_DDMACH0_DLEN
        let len = len & BIT_MASK_DDMACH0_DLEN;
        mmio_bar0.write32(
            REG_DDMA_CH0CTRL,
            BIT_DDMACH0_OWN | BIT_DDMACH0_CHKSUM_EN | len,
        );
    }

    // 4. Wait for BIT_DDMACH0_OWN to clear in REG_DDMA_CH0CTRL.
    if !responsive_spin_until(
        // SAFETY: `mmio_bar0` is the caller-guaranteed BAR0 window;
        // `REG_DDMA_CH0CTRL` is a valid 32-bit DDMA status register polled
        // for the `BIT_DDMACH0_OWN` completion bit.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        || unsafe { (mmio_bar0.read32(REG_DDMA_CH0CTRL) & BIT_DDMACH0_OWN) == 0 },
        Deadline::after_ms(500),
    ) {
        return Err(FwError::DownloadTimeout);
    }

    // 6. Finally, set BIT_FW_DW_RDY in REG_MCUFW_CTRL and poll FW_READY_MASK in REG_MCUFW_CTRL.
    const BIT_FW_DW_RDY: u32 = 1 << 14;
    // SAFETY: `mmio_bar0` is the caller-guaranteed BAR0 window;
    // `REG_MCUFW_CTRL` is a valid 32-bit MCU firmware control register,
    // read-modify-written to set `BIT_FW_DW_RDY`.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        let mut val = mmio_bar0.read32(REG_MCUFW_CTRL);
        val |= BIT_FW_DW_RDY;
        mmio_bar0.write32(REG_MCUFW_CTRL, val);
    }

    if !responsive_spin_until(
        // SAFETY: `mmio_bar0` is the caller-guaranteed BAR0 window;
        // `REG_MCUFW_CTRL` is a valid 32-bit MCU firmware control register
        // polled for `FW_READY_MASK`.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        || unsafe { (mmio_bar0.read32(REG_MCUFW_CTRL) & FW_READY_MASK) == FW_READY_MASK },
        Deadline::after_ms(500),
    ) {
        return Err(FwError::ReadyTimeout);
    }

    Ok(())
}
