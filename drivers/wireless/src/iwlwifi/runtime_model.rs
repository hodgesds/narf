//! Private software firmware fixture. Every DMA/MMIO address below belongs
//! to this fixture; no PCI configuration or physical device is accessed.
use super::*;
use alloc::boxed::Box;
use narf_bus::{
    BarKind, BusAddr, BusDevice, BusDeviceCap, BusKind, DeviceId, MmioRegion, PcieAddr,
};
use narf_capabilities::{Cap, Write};

/// Bounded device-side observation of bytes copied into real command/TX DMA.
/// Snapshots are recorded only after descriptor/doorbell publication, never
/// instead of it. No observer is installed on a physical transport.
#[derive(Clone, Debug)]
pub(in crate::iwlwifi) struct TxTrace(
    alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<alloc::collections::VecDeque<Published>>>,
);

#[derive(Debug)]
pub(in crate::iwlwifi) struct Published {
    pub queue: u16,
    pub pointer: u16,
    pub dma_base: u64,
    pub doorbell: u32,
    pub bytes: Vec<u8>,
    pub descriptor: [u8; 256],
}

impl TxTrace {
    pub(in crate::iwlwifi) fn published(
        &self,
        queue: u16,
        pointer: u16,
        body: &DmaBuffer,
        descriptors: &DmaBuffer,
        slot: usize,
        doorbell: u32,
    ) -> Result<(), &'static str> {
        // Read only CPU mappings of allocations the real queue still owns.
        // The observed descriptor supplies the byte extent; source encoder
        // slices are deliberately unavailable here. Never dereference a DMA
        // address, even when a corrupt descriptor points outside this owner.
        dma_barrier();
        let offset = slot.checked_mul(256).ok_or("private TFH slot overflow")?;
        let descriptor: [u8; 256] = descriptors
            .as_slice()
            .get(offset..offset.checked_add(256).ok_or("private TFH slot overflow")?)
            .ok_or("private TFH slot extent")?
            .try_into()
            .unwrap();
        let count = usize::from(u16::from_le_bytes(descriptor[..2].try_into().unwrap()));
        if !(1..=25).contains(&count) {
            return Err("private TFH transfer count");
        }
        let dma_base = body.dma_addr().raw();
        let mut extent = 0usize;
        for index in 0..count {
            let start = 2 + index * 10;
            let len = usize::from(u16::from_le_bytes(
                descriptor[start..start + 2].try_into().unwrap(),
            ));
            let address = u64::from_le_bytes(descriptor[start + 2..start + 10].try_into().unwrap());
            if len == 0 || dma_base.checked_add(extent as u64) != Some(address) {
                return Err("private TFH points outside retained DMA");
            }
            extent = extent.checked_add(len).ok_or("private TFH body overflow")?;
        }
        let bytes = body
            .as_slice()
            .get(..extent)
            .ok_or("private TFH exceeds retained DMA")?;
        let mut trace = self.0.lock();
        if trace.len() == 256 {
            return Err("private firmware observation overflow");
        }
        trace.push_back(Published {
            queue,
            pointer,
            dma_base,
            doorbell,
            bytes: bytes.to_vec(),
            descriptor,
        });
        Ok(())
    }
    pub(in crate::iwlwifi) fn take(&self) -> Option<Published> {
        self.0.lock().pop_front()
    }
}

pub(in crate::iwlwifi) struct Firmware {
    _registers: Box<[u32]>,
    buffers: Vec<*mut u8>,
    used: *mut u8,
    status: *mut u8,
    next: u16,
}
impl Firmware {
    pub(in crate::iwlwifi) fn tx_write(&self) -> u32 {
        self._registers[tx_gen2::HBUS_TARG_WRPTR as usize / 4]
    }
    pub(in crate::iwlwifi) fn register(&mut self, offset: u32, value: u32) {
        self._registers[offset as usize / 4] = value;
    }
    /// Inject one literal firmware packet into a posted RFH buffer and
    /// publish its actual used-ring descriptor/status, as a device would.
    pub(in crate::iwlwifi) fn inject(
        &mut self,
        command: u8,
        group: u8,
        sequence: u16,
        payload: &[u8],
    ) {
        let index = usize::from(self.next);
        assert!(index < self.buffers.len() && payload.len() + 8 <= RX_BUFFER_BYTES);
        let mut header = [0; 8];
        boot_context::put32(&mut header, 0, payload.len() as u32 + 4);
        header[4] = command;
        header[5] = group;
        boot_context::put16(&mut header, 6, sequence);
        // SAFETY: this single-threaded fixture is the sole device-side
        // writer of a still-posted buffer. Injection occurs between future
        // polls, never during a host copy; all complete extents are checked.
        unsafe {
            core::ptr::copy_nonoverlapping(header.as_ptr(), self.buffers[index], 8);
            core::ptr::copy_nonoverlapping(
                payload.as_ptr(),
                self.buffers[index].add(8),
                payload.len(),
            );
            core::ptr::write_volatile(
                self.used.add(index * 4).cast::<u16>(),
                (self.next + 1).to_le(),
            );
            dma_barrier();
            self.next += 1;
            core::ptr::write_volatile(self.status.cast::<u16>(), self.next.to_le());
        }
    }
    pub(in crate::iwlwifi) fn tx_complete(&mut self, queue: u16, ssn: u16) {
        let mut payload = [0; 48];
        payload[0] = 1;
        payload[40] = 1;
        boot_context::put16(&mut payload, 36, queue);
        boot_context::put32(&mut payload, 44, u32::from(ssn));
        self.inject(0x1c, 0, 0x8000, &payload);
    }
}

pub(in crate::iwlwifi) fn create(full: bool) -> (Hardware, Firmware) {
    create_for_format(full, rx_rfh::CompletionFormat::Bz)
}
pub(in crate::iwlwifi) fn create_for_format(
    full: bool,
    format: rx_rfh::CompletionFormat,
) -> (Hardware, Firmware) {
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    let mut registers = vec![0u32; 0x10000 / 4].into_boxed_slice();
    let region = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: registers.as_mut_ptr() as u64,
        len: 0x10000,
        kind: BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let mut mmio = super::super::IwlMmioImpl::new(region, cap);
    let mut rx = ReceiveQueue::new(format).unwrap();
    rx.publish(&mut mmio).unwrap();
    let firmware = Firmware {
        _registers: registers,
        buffers: rx.buffers.iter().map(DmaBuffer::as_mut_ptr).collect(),
        used: rx.used.as_mut_ptr(),
        status: rx.status.as_mut_ptr(),
        next: 0,
    };
    let mut queue = super::super::data_queue::DataQueue::for_format(format).unwrap();
    let mut response = [0; 8];
    boot_context::put16(&mut response, 0, 17);
    queue.configure(0, 0).unwrap();
    queue.activate(&response).unwrap();
    queue.enable_aggregation();
    if full {
        for _ in 0..super::super::data_queue::DEPTH - 1 {
            queue.send(&mut mmio, &[0; 32], 24, None).unwrap();
        }
    }
    let address = PcieAddr::new(0, 0, 7, 0);
    let hardware = Hardware {
        mmio,
        resources: core::mem::ManuallyDrop::new(Resources {
            rx,
            commands: CommandQueue::new().unwrap(),
            boot: BootImage {
                context: dma_alloc(4096).unwrap(),
                scratch: Some(dma_alloc(4096).unwrap()),
                iml: Some(dma_alloc(4096).unwrap()),
                iml_len: 0,
                _info: Some(dma_alloc(4096).unwrap()),
                prepare: None,
                phy_config: 0,
                _sections: Vec::new(),
            },
            data: vec![queue],
        }),
        device: BusDevice {
            addr: BusAddr::Pcie(address),
            id: DeviceId {
                vendor: 0xffff,
                device: 0xffff,
                class: 0,
                subsystem_vendor: 0,
                subsystem_id: 0,
            },
            kind: BusKind::Pcie {
                addr: address,
                cfg_phys: narf_memory::PhysAddr::new(0),
            },
        },
        cap,
        format,
        interrupts: None,
        notifications: alloc::collections::VecDeque::new(),
        responses: alloc::collections::VecDeque::new(),
        tx_completed: alloc::collections::VecDeque::new(),
        versions: Vec::new(),
        armed: false,
        failed: false,
    };
    (hardware, firmware)
}

/// # Safety
/// Only a hardware object returned by create(), with no outstanding host
/// future/borrow, may be supplied. Its addresses were published to private
/// RAM registers, never a real device; release does not require PCI access.
pub(in crate::iwlwifi) unsafe fn destroy(hardware: Hardware) {
    let mut hardware = core::mem::ManuallyDrop::new(hardware);
    assert!(
        !hardware.armed && hardware.interrupts.is_none() && hardware.device.id.vendor == 0xffff
    );
    // SAFETY: the fixture-only contract proves that no device can reach any
    // allocation, and ManuallyDrop prevents the native PCI teardown path.
    unsafe {
        core::mem::ManuallyDrop::drop(&mut hardware.resources);
        core::ptr::drop_in_place(&mut hardware.notifications);
        core::ptr::drop_in_place(&mut hardware.responses);
        core::ptr::drop_in_place(&mut hardware.tx_completed);
        core::ptr::drop_in_place(&mut hardware.versions);
    };
}

pub(in crate::iwlwifi) fn versions(hardware: &mut Hardware, commands: &[u8]) {
    hardware.versions = commands.to_vec();
}

/// Post-firmware-ready Sc model with no pre-created station queues. The
/// composition must allocate and retain every queue through real commands.
pub(in crate::iwlwifi) fn station_model() -> (Hardware, Firmware, TxTrace) {
    let (mut hardware, firmware) = create(false);
    hardware.resources.data.clear();
    hardware.device.id.device = 0xe340;
    let trace = TxTrace(alloc::sync::Arc::new(narf_lib::sync::IrqSafeSpinLock::new(
        alloc::collections::VecDeque::new(),
    )));
    hardware.resources.commands.trace = Some(trace.clone());
    (hardware, firmware, trace)
}

pub(in crate::iwlwifi) fn retained(hardware: &Hardware) -> (usize, usize, usize) {
    (
        hardware.resources.commands.pending.iter().flatten().count(),
        hardware.resources.data.len(),
        hardware
            .resources
            .data
            .iter()
            .filter(|queue| !queue.is_idle())
            .count(),
    )
}

#[cfg(any(test, feature = "kernel-test"))]
mod trace_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_iwl_trace_reads_actual_published_dma_slot_and_body() -> TestResult {
        let body = dma_alloc(24).unwrap();
        let descriptors = dma_alloc(1024).unwrap();
        let trace = TxTrace(alloc::sync::Arc::new(narf_lib::sync::IrqSafeSpinLock::new(
            alloc::collections::VecDeque::new(),
        )));
        // Independent packed TFH bytes, written to slot3 rather than slot0.
        let mut descriptor = [0u8; 256];
        descriptor[..2].copy_from_slice(&2u16.to_le_bytes());
        descriptor[2..4].copy_from_slice(&20u16.to_le_bytes());
        descriptor[4..12].copy_from_slice(&body.dma_addr().raw().to_le_bytes());
        descriptor[12..14].copy_from_slice(&4u16.to_le_bytes());
        descriptor[14..22].copy_from_slice(&(body.dma_addr().raw() + 20).to_le_bytes());
        write_dma(&body, 0, &[0x5a; 24]);
        write_dma(&descriptors, 3 * 256, &descriptor);
        if trace
            .published(7, 9, &body, &descriptors, 3, 0x70009)
            .is_err()
        {
            return TestResult::Fail("actual TFH/DMA snapshot rejected");
        }
        let observed = trace.take().unwrap();
        write_dma(&body, 0, &[0xa5; 24]);
        if observed.queue != 7
            || observed.pointer != 9
            || observed.dma_base != body.dma_addr().raw()
            || observed.doorbell != 0x70009
            || observed.bytes != [0x5a; 24]
            || observed.descriptor != descriptor
            || trace
                .published(7, 10, &body, &descriptors, 3, 0x7000a)
                .is_err()
            || trace.take().unwrap().bytes != [0xa5; 24]
        {
            return TestResult::Fail("trace did not snapshot actual descriptor slot/body");
        }
        if trace.published(7, 11, &body, &descriptors, 2, 0x7000b)
            != Err("private TFH transfer count")
        {
            return TestResult::Fail("unwritten TFH slot was treated as published DMA");
        }
        descriptor[4..12].copy_from_slice(&(body.dma_addr().raw() + 1).to_le_bytes());
        write_dma(&descriptors, 3 * 256, &descriptor);
        if trace.published(7, 12, &body, &descriptors, 3, 0x7000c)
            != Err("private TFH points outside retained DMA")
            || trace.take().is_some()
        {
            return TestResult::Fail("trace followed a TFH address outside retained DMA");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/runtime",
        smoke_iwl_trace_reads_actual_published_dma_slot_and_body
    );
}
