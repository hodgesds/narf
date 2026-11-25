//! Register ownership for the module build: `mmio.rs`'s names over the KABI.
//!
//! Built in, every register access runs inside an invocation of the bound
//! device's capability and PCI command changes go through `narf_bus::pci`.
//! In the `.ko` the kernel holds that capability: each `narf_mmio_*` /
//! `narf_pci_*` call is checked against the probe token, and device teardown
//! revokes it (every later access then reads all-ones and writes nothing).
use super::transport::IwlMmio;
use crate::iwlwifi::module::kernel::narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use crate::iwlwifi::module::kernel::narf_capabilities::{Cap, CapError, Write};
use crate::iwlwifi::module::{device, kernel::narf_bus};

/// KABI exports the register layer calls.
mod ffi {
    unsafe extern "C" {
        pub fn narf_pci_prepare_probe(dev: u64) -> i32;
        pub fn narf_pci_enable(dev: u64, cmd_bits: u16) -> i32;
        pub fn narf_pci_disable(dev: u64, cmd_bits: u16) -> i32;
        pub fn narf_bar_map(dev: u64, bar_idx: u8) -> u64;
        pub fn narf_bar_len(dev: u64, bar: u64, out_len: *mut u64) -> i32;
    }
}

/// `PCI_COMMAND_MEMORY` / `_MASTER`.
const MEM_SPACE: u16 = 0x2;
const BUS_MASTER: u16 = 0x4;

/// Park inherited decode and mastering (`narf_pci_prepare_probe` also puts
/// the function in D0). Valid only before the context owns resources, which
/// is the only place the module calls it: probe.
pub(super) fn park(
    _device: &BusDevice,
    _cap: &Cap<BusDeviceCap, Write>,
) -> Result<(), &'static str> {
    // SAFETY: argument-only call on our probe token.
    if unsafe { ffi::narf_pci_prepare_probe(device()) } != 0 {
        return Err("cannot park Wi-Fi PCI");
    }
    Ok(())
}

/// Park, map BAR0 and enable memory decode with mastering off — the
/// built-in `map`'s sequence. The BAR's length comes from `narf_bar_len`.
pub(super) fn map(
    device_: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
) -> Result<MmioRegion, &'static str> {
    park(device_, cap)?;
    // SAFETY: argument-only call on our probe token.
    let bar = unsafe { ffi::narf_bar_map(device(), 0) };
    let mut len = 0u64;
    // SAFETY: `len` is a live local.
    if bar == 0 || unsafe { ffi::narf_bar_len(device(), bar, &mut len) } != 0 {
        return Err("cannot map Wi-Fi BAR0");
    }
    // SAFETY: argument-only call on our probe token.
    if unsafe { ffi::narf_pci_enable(device(), MEM_SPACE) } != 0 {
        return Err("cannot enable Wi-Fi memory decode");
    }
    set_master(device_, cap, false)?;
    Ok(narf_bus::MmioRegion { len, bar })
}

/// Bus mastering on or off, verified by the kernel's readback.
pub(super) fn set_master(
    _device: &BusDevice,
    _cap: &Cap<BusDeviceCap, Write>,
    enabled: bool,
) -> Result<(), &'static str> {
    // SAFETY: argument-only calls on our probe token.
    let rc = unsafe {
        if enabled {
            ffi::narf_pci_enable(device(), BUS_MASTER)
        } else {
            ffi::narf_pci_disable(device(), BUS_MASTER)
        }
    };
    if rc != 0 {
        return Err("cannot change Wi-Fi bus mastering");
    }
    Ok(())
}

/// Run `operation` under the device authority (the KABI checks the token on
/// each access inside it).
pub(super) fn invoke<T>(
    cap: &Cap<BusDeviceCap, Write>,
    operation: impl FnOnce() -> T,
) -> Result<T, CapError> {
    struct Registers<F>(F);
    impl<T, F: FnOnce() -> T>
        crate::iwlwifi::module::kernel::narf_capabilities::CapOp<BusDeviceCap, Write>
        for Registers<F>
    {
        type Output = T;
        fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
            Ok(self.0())
        }
    }
    cap.invoke(Registers(operation))
}

/// BAR0 registers as the transport sees them.
pub(super) struct IwlMmioImpl {
    region: MmioRegion,
    cap: Cap<BusDeviceCap, Write>,
}
impl IwlMmioImpl {
    pub(super) fn new(region: MmioRegion, cap: Cap<BusDeviceCap, Write>) -> Self {
        Self { region, cap }
    }
    pub(super) fn interrupts(
        &self,
        device: &BusDevice,
    ) -> Result<super::iwl_msix::Interrupts, &'static str> {
        super::iwl_msix::Interrupts::new(&self.cap, device, self.region)
    }
    fn valid(&self, offset: u32) -> bool {
        offset & 3 == 0
            && u64::from(offset)
                .checked_add(4)
                .is_some_and(|end| end <= self.region.len)
    }
}
impl IwlMmio for IwlMmioImpl {
    fn read(&mut self, offset: u32) -> u32 {
        if !self.valid(offset) {
            return u32::MAX;
        }
        // SAFETY: the complete naturally aligned dword is inside BAR0; the
        // kernel bounds-checks it again against the token's mapping.
        unsafe { self.region.read32(u64::from(offset)) }
    }
    fn write(&mut self, offset: u32, value: u32) {
        if !self.valid(offset) {
            return;
        }
        // SAFETY: as `read`.
        unsafe { self.region.write32(u64::from(offset), value) };
    }
}
