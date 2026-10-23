//! Private coherent AX CH12 backend. Initialization requires stopped PCI DMA;
//! activation requires the complete PCIe/BDRAM/DLE firmware-download owner.
use super::{
    command_queue::{self, CommandQueue, Error, Kind},
    dma::{addr_set_for_chip, TxRingRegs},
    mac::ChipId,
    power::Io,
    power_native::NativeIo,
};
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent_masked, DmaBuffer};
use narf_lib::id::DomainId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Unpublished,
    Configuring,
    Configured,
    Active,
    Terminal,
}
pub struct Native {
    io: NativeIo,
    device: BusDevice,
    authority: Cap<BusDeviceCap, Write>,
    chip: ChipId,
    regs: TxRingRegs,
    ring: Option<DmaBuffer>,
    queue: CommandQueue<DmaBuffer>,
    depth: u16,
    armed: bool,
    state: State,
}
fn barrier() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    // SAFETY: device DMA ownership requires the outer-shareable domain.
    unsafe {
        core::arch::asm!("dmb osh", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
impl Native {
    /// # Safety
    /// Device/capability/BAR identify the same exclusively owned powered AX
    /// function. Hardware DMA has been independently stopped/fenced. No
    /// concurrent PHY/EFUSE/firmware/ring/reset operation may access this BAR.
    /// The coherent DMA addresses must be valid for this device; the currently
    /// unimplemented per-domain IOMMU path is explicitly rejected.
    pub unsafe fn new(
        device: BusDevice,
        mmio: MmioRegion,
        authority: Cap<BusDeviceCap, Write>,
        chip: ChipId,
        cut: u8,
        depth: u16,
    ) -> Result<Self, Error> {
        authority.check_live().map_err(|_| Error::Access)?;
        if narf_io::iommu::mode() == narf_io::iommu::IommuMode::PerDomain
            || chip == ChipId::Rtl8922A
            || device.id.vendor != 0x10ec
            || ChipId::from_pci_did(device.id.device) != Some(chip)
        {
            return Err(Error::Unsupported);
        }
        // SAFETY: caller's exclusive, same-device Device-mapped BAR contract.
        let mut io =
            unsafe { NativeIo::new(mmio, authority, chip, cut) }.map_err(|_| Error::Access)?;
        let regs = addr_set_for_chip(chip).tx[12];
        // Actual register operation invokes current authority before allocating.
        if io.read32(regs.idx as u32).map_err(|_| Error::Access)? == u32::MAX {
            return Err(Error::Access);
        }
        let command = crate::rtw88::pci_park::invoke(&authority, || {
            narf_bus::pci::read_command(&authority, &device)
        })
        .map_err(|_| Error::Access)?
        .map_err(|_| Error::Access)?;
        if command & narf_bus::pci::cmd::BUS_MASTER != 0 {
            return Err(Error::Busy);
        }
        let queue = CommandQueue::new(depth)?;
        let ring =
            alloc_coherent_masked(usize::from(depth) * 8, DomainId::DRIVER_0, (1u64 << 40) - 1)
                .map_err(|_| Error::NoMemory)?;
        // SAFETY: fresh, owned coherent allocation covers all depth*8 bytes.
        unsafe {
            core::ptr::write_bytes(ring.as_mut_ptr(), 0, usize::from(depth) * 8);
        }
        ring.sync(0, usize::from(depth) * 8);
        Ok(Self {
            io,
            device,
            authority,
            chip,
            regs,
            ring: Some(ring),
            queue,
            depth,
            armed: false,
            state: State::Unpublished,
        })
    }
    fn command(&self) -> Result<u16, Error> {
        crate::rtw88::pci_park::invoke(&self.authority, || {
            narf_bus::pci::read_command(&self.authority, &self.device)
        })
        .map_err(|_| Error::Access)?
        .map_err(|_| Error::Access)
    }
    /// # Safety
    /// Same stopped/fenced/serialized contract as new; BDRAM and hardware
    /// indices have been reset independently, with CH12 DMA disabled.
    pub unsafe fn configure(&mut self) -> Result<(), Error> {
        if self.state != State::Unpublished {
            return Err(Error::Terminal);
        }
        self.state = State::Configuring;
        if self.command()? & narf_bus::pci::cmd::BUS_MASTER != 0 {
            return Err(Error::Busy);
        }
        self.configure_registers()
    }
    fn configure_registers(&mut self) -> Result<(), Error> {
        let ring = self.ring.as_ref().ok_or(Error::Terminal)?;
        let address = ring.dma_addr().raw();
        if address
            .checked_add(usize::from(self.depth) as u64 * 8 - 1)
            .is_none_or(|end| end >= 1 << 40)
        {
            return Err(Error::BadAddress);
        }
        // Pin even the ring before the first potentially visible base write.
        self.armed = true;
        barrier();
        self.io
            .write32(self.regs.desa_l as u32, address as u32)
            .map_err(|_| Error::Access)?;
        self.io
            .write32(self.regs.desa_h as u32, (address >> 32) as u32)
            .map_err(|_| Error::Access)?;
        self.io
            .write16(self.regs.num as u32, self.depth)
            .map_err(|_| Error::Access)?;
        if self
            .io
            .read32(self.regs.desa_l as u32)
            .map_err(|_| Error::Access)?
            != address as u32
            || self
                .io
                .read32(self.regs.desa_h as u32)
                .map_err(|_| Error::Access)?
                != (address >> 32) as u32
            || self
                .io
                .read16(self.regs.num as u32)
                .map_err(|_| Error::Access)?
                != self.depth
            || self
                .io
                .read32(self.regs.idx as u32)
                .map_err(|_| Error::Access)?
                & 0x0fff_0fff
                != 0
        {
            return Err(Error::BadIndex);
        }
        self.state = State::Configured;
        Ok(())
    }
    /// # Safety
    /// Caller completed the full PCIe/BDRAM/DLE/HFC firmware-download setup,
    /// enabled only CH12 TX DMA and PCI bus mastering, and retains that setup.
    pub unsafe fn activate(&mut self) -> Result<(), Error> {
        if self.state != State::Configured {
            return Err(Error::Terminal);
        }
        self.state = State::Terminal;
        if self.command()? & narf_bus::pci::cmd::BUS_MASTER == 0 {
            return Err(Error::Busy);
        }
        self.activate_registers()
    }
    fn activate_registers(&mut self) -> Result<(), Error> {
        let value = self
            .io
            .read32(self.regs.idx as u32)
            .map_err(|_| Error::Access)?;
        if value & 0x0fff_0fff != 0 || value == u32::MAX {
            return Err(Error::BadIndex);
        }
        self.state = State::Active;
        Ok(())
    }
    pub fn io(&mut self) -> &mut NativeIo {
        &mut self.io
    }
    pub fn poll(&mut self) -> Result<usize, Error> {
        if self.state != State::Active {
            return Err(Error::Terminal);
        }
        let value = match self.io.read32(self.regs.idx as u32) {
            Ok(value) if value != u32::MAX => value,
            _ => {
                self.state = State::Terminal;
                return Err(Error::Access);
            }
        };
        barrier();
        // Linux TXBD_HW_IDX_MASK=GENMASK(27,16); host WP occupies bits11:0.
        let read = ((value >> 16) & 0xfff) as u16;
        let result = self.queue.observe(read);
        match result {
            Ok(retired) => {
                let count = retired.len();
                drop(retired);
                Ok(count)
            }
            Err(error) => {
                self.state = State::Terminal;
                Err(error)
            }
        }
    }
    /// A successful return means publication, never firmware execution or DMA
    /// retirement. The retained queue owns every command throughout its wait.
    pub async fn send(&mut self, kind: Kind, bytes: &[u8]) -> Result<(), Error> {
        if self.state != State::Active {
            return Err(Error::Terminal);
        }
        self.poll()?;
        let start = self.io.now_us();
        while self.queue.is_full() {
            if self.io.now_us().saturating_sub(start) >= 400_000 {
                self.state = State::Terminal;
                return Err(Error::Timeout);
            }
            self.io.delay_us(50).await;
            self.poll()?;
        }
        let header = command_queue::descriptor(self.chip, kind, bytes.len())?;
        let packet = alloc_coherent_masked(
            header.len() + bytes.len(),
            DomainId::DRIVER_0,
            (1u64 << 40) - 1,
        )
        .map_err(|_| Error::NoMemory)?;
        let bd = command_queue::txbd(packet.dma_addr().raw(), header.len() + bytes.len())?;
        // SAFETY: fresh packet allocation covers descriptor followed by bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(header.as_ptr(), packet.as_mut_ptr(), header.len());
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                packet.as_mut_ptr().add(header.len()),
                bytes.len(),
            );
        }
        packet.sync(0, header.len() + bytes.len());
        let ring = self.ring.as_ref().ok_or(Error::Terminal)?;
        let io = &mut self.io;
        let idx = self.regs.idx as u32;
        let result = self.queue.submit(packet, |slot, next, _packet| {
            let offset = usize::from(slot) * 8;
            // SAFETY: validated queue slot is below ring depth; eight-byte BD.
            unsafe {
                core::ptr::copy_nonoverlapping(bd.as_ptr(), ring.as_mut_ptr().add(offset), 8);
            }
            ring.sync(offset, 8);
            barrier();
            // Only write the HOST half. A32-bit RMW would also overwrite HW RP.
            io.write16(idx, next).map_err(|_| Error::Access)
        });
        match result {
            Ok(_) => Ok(()),
            Err((error, unpublished)) => {
                drop(unpublished);
                self.state = State::Terminal;
                Err(error)
            }
        }
    }
    /// # Safety
    /// Hardware stop/idle and all DMA/prefetch fences are complete. This cannot
    /// be established solely by revoking a capability or clearing PCI BME.
    pub unsafe fn reclaim_fenced(&mut self) {
        // SAFETY: caller proves all queued and multi-tag references are gone.
        unsafe {
            self.queue.reclaim_fenced();
        }
        self.armed = false;
        self.state = State::Terminal;
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        if self.armed {
            if let Some(ring) = self.ring.take() {
                core::mem::forget(ring);
            }
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "command_native_tests.rs"]
mod tests;
