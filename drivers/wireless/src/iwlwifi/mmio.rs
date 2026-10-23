//! Live-capability register ownership for native Intel PCIe transports.
use super::transport::IwlMmio;
use narf_bus::BusDevice;

pub(super) fn park(device: &BusDevice, cap: &Cap<BusDeviceCap, Write>) -> Result<(), &'static str> {
    invoke(cap, || {
        use narf_bus::pci::{
            self,
            cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE},
        };
        pci::clear_command(cap, device, BUS_MASTER | MEM_SPACE)
            .map_err(|_| "cannot park Wi-Fi PCI")?;
        pci::set_command(cap, device, INTX_DISABLE).map_err(|_| "cannot park Wi-Fi INTx")?;
        if pci::read_command(cap, device).map_err(|_| "cannot read Wi-Fi PCI")?
            & (BUS_MASTER | MEM_SPACE | INTX_DISABLE)
            != INTX_DISABLE
        {
            return Err("Wi-Fi PCI parking readback failed");
        }
        Ok(())
    })
    .map_err(|_| "Wi-Fi authority revoked")?
}
pub(super) fn map(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
) -> Result<MmioRegion, &'static str> {
    park(device, cap)?;
    invoke(cap, || {
        // SAFETY: this probe exclusively owns the function, and decode/BME
        // were verified off before BAR sizing. Device mapping is mandatory.
        let region =
            unsafe { narf_bus::map_bar_control(device, 0) }.map_err(|_| "cannot map Wi-Fi BAR0")?;
        narf_bus::pci::set_command(
            cap,
            device,
            narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE,
        )
        .map_err(|_| "cannot enable Wi-Fi memory decode")?;
        set_master(device, cap, false)?;
        Ok(region)
    })
    .map_err(|_| "Wi-Fi authority revoked")?
}
pub(super) fn set_master(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
    enabled: bool,
) -> Result<(), &'static str> {
    invoke(cap, || {
        use narf_bus::pci::{
            self,
            cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE},
        };
        if enabled {
            pci::set_command(cap, device, BUS_MASTER)
        } else {
            pci::clear_command(cap, device, BUS_MASTER)
        }
        .map_err(|_| "cannot change Wi-Fi bus mastering")?;
        let command = pci::read_command(cap, device).map_err(|_| "cannot read Wi-Fi PCI")?;
        if command & (BUS_MASTER | MEM_SPACE | INTX_DISABLE)
            != MEM_SPACE | INTX_DISABLE | if enabled { BUS_MASTER } else { 0 }
        {
            return Err("Wi-Fi PCI command readback failed");
        }
        Ok(())
    })
    .map_err(|_| "Wi-Fi authority revoked")?
}
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Write};

pub(super) fn invoke<T>(
    cap: &Cap<BusDeviceCap, Write>,
    operation: impl FnOnce() -> T,
) -> Result<T, CapError> {
    struct Registers<F>(F);
    impl<T, F: FnOnce() -> T> CapOp<BusDeviceCap, Write> for Registers<F> {
        type Output = T;
        fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
            Ok(self.0())
        }
    }
    cap.invoke(Registers(operation))
}

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
        device: &narf_bus::BusDevice,
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
    fn authorized(&self) -> bool {
        self.cap.invoke(NoopOp).is_ok()
    }
    fn read(&mut self, offset: u32) -> u32 {
        if !self.valid(offset) {
            return u32::MAX;
        }
        invoke(&self.cap, || {
            // SAFETY: the complete naturally aligned dword is inside the
            // exclusively owned BAR and the actual read executes in CapOp.
            unsafe { self.region.read32(u64::from(offset)) }
        })
        .unwrap_or(u32::MAX)
    }
    fn write(&mut self, offset: u32, value: u32) {
        if !self.valid(offset) {
            return;
        }
        let _ = invoke(&self.cap, || {
            // SAFETY: checked aligned extent, exclusive BAR and live invocation.
            unsafe { self.region.write32(u64::from(offset), value) };
        });
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_iwl_native_capability_and_complete_dword_bounds() -> TestResult {
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        let mut storage = Box::new([0x11223344u32, 0x55667788]);
        let region = MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: storage.as_mut_ptr() as u64,
            len: 8,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let mut mmio = IwlMmioImpl::new(region, cap);
        if !mmio.authorized() || mmio.read(0) != storage[0] || mmio.read(4) != storage[1] {
            return TestResult::Fail("live native register scope did not execute");
        }
        mmio.write(4, 0xaabbccdd);
        for offset in [1, 2, 6, 8, u32::MAX] {
            if mmio.read(offset) != u32::MAX {
                return TestResult::Fail("unaligned or partial dword admitted");
            }
            mmio.write(offset, 0);
        }
        if *storage != [0x11223344, 0xaabbccdd] {
            return TestResult::Fail("out-of-range native write changed storage");
        }
        cap.revoke();
        mmio.write(0, 0);
        if mmio.authorized() || mmio.read(0) != u32::MAX || *storage != [0x11223344, 0xaabbccdd] {
            return TestResult::Fail("revoked authority reached actual native register access");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwl_native_capability_and_complete_dword_bounds
    );

    fn smoke_iwl_revocation_prevents_actual_queue_submission() -> TestResult {
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        let region = MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 0x10000,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let mut mmio = IwlMmioImpl::new(region, cap);
        let mut commands = super::super::runtime::CommandQueue::new().unwrap();
        let mut receive =
            super::super::runtime::ReceiveQueue::new(super::super::rx_rfh::CompletionFormat::Ax210)
                .unwrap();
        let mut data = super::super::data_queue::DataQueue::new().unwrap();
        data.configure(1, 0).unwrap();
        data.activate(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        cap.revoke();
        if commands.send(&mut mmio, 1, 2, 0, &[3; 4]) != Err("Wi-Fi authority revoked")
            || receive.publish(&mut mmio) != Err("Wi-Fi authority revoked")
            || !matches!(receive.drain(&mut mmio), Err("Wi-Fi authority revoked"))
            || data.send(&mut mmio, &[0; 24], 24, None) != Err("Wi-Fi authority revoked")
            || !data.is_idle()
        {
            return TestResult::Fail(
                "revoked capability admitted actual command/RX/data publication",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi",
        smoke_iwl_revocation_prevents_actual_queue_submission
    );
}
