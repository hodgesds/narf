//! Raphael's mode 2 reset, after `nv_asic_mode2_reset`.
//!
//! `nv_asic_reset_method` picks AMD_RESET_METHOD_MODE2 for MP1 13.0.5.
//! The sequence:
//! 1. Set the VBIOS engine-hung scratch bit
//!    (`amdgpu_atombios_scratch_regs_engine_hung`).
//! 2. Clear PCI bus mastering, and cache the config state the reset may
//!    disturb (the command register and BARs).
//! 3. Send PMFW `GfxDeviceDriverReset(MODE2_RESET)`.
//! 4. Restore the config state.
//! 5. Wait for NBIO MEMSIZE to stop reading all-ones (`adev->usec_timeout`).
//! 6. Clear the scratch bit.
//!
//! A failed PMFW message is reported after the config state is restored and
//! the scratch bit cleared, as Linux does. The caller re-initializes every
//! IP afterwards (`amdgpu_device_reinit_after_reset`).
use crate::{amdgpu::AmdGpu, amdgpu_smu_raphael as smu};
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, CapError, CapOp, Write};

const ATOM_S3_ASIC_GUI_ENGINE_HUNG: u32 = 0x2000_0000; // linux: ATOM_S3_ASIC_GUI_ENGINE_HUNG
const PCI_COMMAND: u16 = 0x04; // linux: PCI_COMMAND
const PCI_COMMAND_MASTER: u32 = 0x4; // linux: PCI_COMMAND_MASTER
const PCI_BASE_ADDRESS_0: u16 = 0x10; // linux: PCI_BASE_ADDRESS_0
const BARS: usize = 6; // linux: n/a (PCI_STD_NUM_BARS)
const MEMSIZE: u64 = 0xc3; // linux: n/a (nbio_v7_2_get_memsize: RCC_DEV0_EPF0_RCC_CONFIG_MEMSIZE)
const MEMSIZE_TIMEOUT_MS: u64 = 100; // linux: AMDGPU_MAX_USEC_TIMEOUT / 1000

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not Raphael, or its NBIO banks did not resolve.
    Unsupported,
    Revoked,
    /// A PCI config access failed.
    Pci,
    /// PMFW refused or missed the reset message.
    Smu(smu::Error),
    /// MEMSIZE still read all-ones after the timeout: the device is gone.
    Timeout,
}

/// What the sequence touches, so its order can be checked without a GPU.
pub(crate) trait Io {
    /// BIOS_SCRATCH_3, when the VBIOS names the scratch block.
    fn scratch3(&mut self) -> Option<u32>;
    fn set_scratch3(&mut self, value: u32);
    fn config(&mut self, offset: u16) -> Result<u32, Error>;
    fn set_config(&mut self, offset: u16, value: u32) -> Result<(), Error>;
    async fn pmfw_mode2(&mut self) -> Result<(), Error>;
    fn memsize(&mut self) -> Result<u32, Error>;
    async fn sleep_ms(&mut self, ms: u64);
}

/// `nv_asic_mode2_reset` over `io`.
pub(crate) async fn sequence(io: &mut impl Io) -> Result<(), Error> {
    if let Some(value) = io.scratch3() {
        io.set_scratch3(value | ATOM_S3_ASIC_GUI_ENGINE_HUNG);
    }
    let command = io.config(PCI_COMMAND)?;
    let mut bars = [0; BARS];
    for (i, bar) in bars.iter_mut().enumerate() {
        *bar = io.config(PCI_BASE_ADDRESS_0 + 4 * i as u16)?;
    }
    io.set_config(PCI_COMMAND, command & !PCI_COMMAND_MASTER)?;
    let reset = io.pmfw_mode2().await;
    for (i, &bar) in bars.iter().enumerate() {
        io.set_config(PCI_BASE_ADDRESS_0 + 4 * i as u16, bar)?;
    }
    io.set_config(PCI_COMMAND, command)?;
    let mut alive = false;
    for _ in 0..MEMSIZE_TIMEOUT_MS {
        if io.memsize()? != u32::MAX {
            alive = true;
            break;
        }
        io.sleep_ms(1).await;
    }
    if let Some(value) = io.scratch3() {
        io.set_scratch3(value & !ATOM_S3_ASIC_GUI_ENGINE_HUNG);
    }
    reset?;
    if !alive {
        return Err(Error::Timeout);
    }
    Ok(())
}

/// The live device: BAR5 registers under PCI authority, its PCI function's
/// config space, and the graphics SMU mailbox.
struct Device<'a> {
    gpu: &'a AmdGpu,
    authority: &'a Cap<BusDeviceCap, Write>,
    device: &'a BusDevice,
    smu: &'a mut smu::Smu,
    /// BIOS_SCRATCH_3's byte offset, bounded inside BAR5.
    scratch3: Option<u64>,
    /// NBIO MEMSIZE's byte offset.
    memsize: u64,
}
struct Read32<'a>(&'a narf_bus::MmioRegion, u64);
impl CapOp<BusDeviceCap, Write> for Read32<'_> {
    type Output = u32;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<u32, CapError> {
        // SAFETY: the offset was bounded inside the live BAR5 mapping.
        Ok(unsafe { self.0.read32(self.1) })
    }
}
struct Write32<'a>(&'a narf_bus::MmioRegion, u64, u32);
impl CapOp<BusDeviceCap, Write> for Write32<'_> {
    type Output = ();
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<(), CapError> {
        // SAFETY: the offset was bounded inside the live BAR5 mapping.
        unsafe { self.0.write32(self.1, self.2) };
        Ok(())
    }
}
impl Io for Device<'_> {
    fn scratch3(&mut self) -> Option<u32> {
        let at = self.scratch3?;
        self.authority.invoke(Read32(&self.gpu.regs, at)).ok()
    }
    fn set_scratch3(&mut self, value: u32) {
        if let Some(at) = self.scratch3 {
            let _ = self.authority.invoke(Write32(&self.gpu.regs, at, value));
        }
    }
    fn config(&mut self, offset: u16) -> Result<u32, Error> {
        narf_bus::pci::read_config32(self.authority, self.device, offset).map_err(|_| Error::Pci)
    }
    fn set_config(&mut self, offset: u16, value: u32) -> Result<(), Error> {
        narf_bus::pci::write_config32(self.authority, self.device, offset, value)
            .map_err(|_| Error::Pci)
    }
    async fn pmfw_mode2(&mut self) -> Result<(), Error> {
        // SAFETY: forwarded from `mode2`'s contract.
        unsafe { self.smu.mode2_reset() }.await.map_err(Error::Smu)
    }
    fn memsize(&mut self) -> Result<u32, Error> {
        self.authority
            .invoke(Read32(&self.gpu.regs, self.memsize))
            .map_err(|_| Error::Revoked)
    }
    async fn sleep_ms(&mut self, ms: u64) {
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(ms).as_instant()).await;
    }
}

/// BIOS_SCRATCH_3's byte offset from the VBIOS firmware info
/// (`bios_scratch_reg_startaddr`), when it lies inside BAR5.
fn scratch3(gpu: &AmdGpu) -> Option<u64> {
    use crate::atombios::{header::parse_rom_header, tables::MasterDataTable};
    let bios = gpu.vbios.as_ref()?.bytes();
    let header = parse_rom_header(bios).ok()?;
    let tables = MasterDataTable::parse(bios, &header).ok()?;
    let firmware = crate::amdgpu_atom_fwinfo::parse(tables.table_slice(4)?).ok()?;
    let base = firmware.bios_scratch_reg_startaddr;
    // linux: n/a (BIOS_SCRATCH_3 is the scratch block's fourth dword)
    let at = (u64::from(base) + 3) * 4;
    (base != 0 && at.checked_add(4)? <= gpu.regs.len).then_some(at)
}

/// Run the mode 2 reset on Raphael's live device.
///
/// # Safety
/// Every owner of the graphics, SDMA, media and interrupt engines is
/// quiesced, no client work is admitted, the PSP has released its TMR, and
/// the caller re-initializes every engine before anything uses them.
pub(crate) async unsafe fn mode2(
    gpu: &AmdGpu,
    authority: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
    smu: &mut smu::Smu,
) -> Result<(), Error> {
    let banks = crate::amdgpu_nbio_v7_2::Banks::resolve(gpu).ok_or(Error::Unsupported)?;
    let memsize = banks.bif + MEMSIZE * 4;
    if memsize + 4 > gpu.regs.len {
        return Err(Error::Unsupported);
    }
    let mut io = Device {
        gpu,
        authority,
        device,
        smu,
        scratch3: scratch3(gpu),
        memsize,
    };
    sequence(&mut io).await
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_raphael_reset_tests.rs"]
mod tests;
