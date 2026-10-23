//! Private software firmware fixture. Every DMA/MMIO address below belongs
//! to this fixture; no PCI configuration or physical device is accessed.
use super::*;
use alloc::boxed::Box;
use narf_bus::{
    BarKind, BusAddr, BusDevice, BusDeviceCap, BusKind, DeviceId, MmioRegion, PcieAddr,
};
use narf_capabilities::{Cap, Write};

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
        assert!(index < 32 && payload.len() + 8 <= RX_BUFFER_BYTES);
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
    let mut rx = ReceiveQueue::new(rx_rfh::CompletionFormat::Bz).unwrap();
    rx.publish(&mut mmio).unwrap();
    let firmware = Firmware {
        _registers: registers,
        buffers: rx.buffers.iter().map(DmaBuffer::as_mut_ptr).collect(),
        used: rx.used.as_mut_ptr(),
        status: rx.status.as_mut_ptr(),
        next: 0,
    };
    let mut queue = super::super::data_queue::DataQueue::new().unwrap();
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
                scratch: dma_alloc(4096).unwrap(),
                iml: dma_alloc(4096).unwrap(),
                iml_len: 0,
                _info: dma_alloc(4096).unwrap(),
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
        format: rx_rfh::CompletionFormat::Bz,
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
