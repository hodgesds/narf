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

// Linux pci.c::rtw89_pci_setup_mapping negotiates36 bits (then32). The
// baseline TXBD/RXBD wire fields can encode40; that is not a device DMA grant.
const DEVICE_DMA_MASK: u64 = (1u64 << 36) - 1;

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
    bdram: super::bdram::Bdram,
    pcie: super::pcie::Pcie,
    basic: super::pci_basic::Basic,
    factory: Option<super::factory::Factory>,
    fifo: super::fifo::Fifo,
    cut: u8,
    device: BusDevice,
    authority: Cap<BusDeviceCap, Write>,
    chip: ChipId,
    regs: TxRingRegs,
    ring: Option<DmaBuffer>,
    queue: CommandQueue<DmaBuffer>,
    depth: u16,
    armed: bool,
    state: State,
    receive: super::rx_dma::Rx,
    radio: super::rf_access::Rf,
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
        let io = unsafe { NativeIo::new(mmio, authority, chip, cut) }.map_err(|_| Error::Access)?;
        Self::allocate(
            super::cold_native::Owned {
                io,
                device,
                authority,
            },
            depth,
            super::pci_basic::Basic::default(),
            None,
        )
    }
    pub(super) fn from_cold(
        prepared: super::cold::Prepared<super::cold_native::Owned>,
        depth: u16,
    ) -> Result<Self, Error> {
        let (backend, basic, factory) = prepared.into_parts();
        let identity = factory.identity().ok_or(Error::Terminal)?;
        if backend.io.profile() != (identity.chip(), identity.cut())
            || basic.state() != super::pci_basic::State::Ready
        {
            return Err(Error::Terminal);
        }
        Self::allocate(backend, depth, basic, Some(factory))
    }
    fn allocate(
        backend: super::cold_native::Owned,
        depth: u16,
        basic: super::pci_basic::Basic,
        factory: Option<super::factory::Factory>,
    ) -> Result<Self, Error> {
        let super::cold_native::Owned {
            mut io,
            device,
            authority,
        } = backend;
        let (chip, cut) = io.profile();
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
            alloc_coherent_masked(usize::from(depth) * 8, DomainId::DRIVER_0, DEVICE_DMA_MASK)
                .map_err(|_| Error::NoMemory)?;
        // SAFETY: fresh, owned coherent allocation covers all depth*8 bytes.
        unsafe {
            core::ptr::write_bytes(ring.as_mut_ptr(), 0, usize::from(depth) * 8);
        }
        ring.sync(0, usize::from(depth) * 8);
        Ok(Self {
            io,
            bdram: super::bdram::Bdram::default(),
            pcie: super::pcie::Pcie::default(),
            basic,
            factory,
            fifo: super::fifo::Fifo::default(),
            cut,
            device,
            authority,
            chip,
            regs,
            ring: Some(ring),
            queue,
            depth,
            armed: false,
            state: State::Unpublished,
            receive: super::rx_dma::Rx::default(),
            radio: super::rf_access::Rf::default(),
        })
    }
    pub(super) fn identity(&self) -> Option<super::factory::Identity> {
        self.factory.as_ref().and_then(|factory| factory.identity())
    }
    /// Continue the same cold/firmware backend; never reset its ring indices or
    /// release the multi-tag quarantine merely because WCPU reports initialized.
    /// # Safety
    /// Only the retained Startup attempt may call this after its Firmware is
    /// Running. That caller terminalizes this Native on failure/cancellation,
    /// retains all published DMA and excludes packet/IRQ/reset/radio producers.
    pub(super) async unsafe fn prepare_mac(
        &mut self,
        mac: &mut super::mac_runtime::Mac,
    ) -> Result<(), super::power::Error> {
        use super::power::Error as RegisterError;
        if self.state != State::Active
            || self.chip != ChipId::Rtl8852B
            || self
                .factory
                .as_ref()
                .is_none_or(|factory| factory.b_phycap().is_none())
        {
            return Err(RegisterError::Unsupported);
        }
        let command = self.command().map_err(|_| RegisterError::Access)?;
        if command & (narf_bus::pci::cmd::BUS_MASTER | narf_bus::pci::cmd::MEM_SPACE)
            != narf_bus::pci::cmd::BUS_MASTER | narf_bus::pci::cmd::MEM_SPACE
        {
            return Err(RegisterError::Access);
        }
        let start = self.io.now_us();
        loop {
            self.poll().map_err(|_| RegisterError::Access)?;
            if self.queue.pending() == 0 {
                break;
            }
            if self.io.now_us().saturating_sub(start) >= 400_000 {
                return Err(RegisterError::Timeout);
            }
            self.io.delay_us(50).await;
        }
        // SAFETY: the actual retained startup/firmware owner above has drained
        // CH12 consumption and keeps all old rings/quarantined DMA alive.
        unsafe {
            mac.prepare(&mut self.io, self.factory.as_ref().unwrap())
                .await
        }
    }
    /// Activate only the retained CH12 path. No RX base is published: both RX
    /// HCI layers stay disabled, WPDMA and every packet TX channel stay stopped.
    /// PCI BME is the final publication and is read back under current authority.
    pub(super) fn enable_download(&mut self) -> Result<(), Error> {
        if self.state != State::Configured
            || self.identity().is_none()
            || self.basic.state() != super::pci_basic::State::Ready
            || self.pcie.state() != super::pcie::State::Ready
            || self.bdram.state() != super::bdram::State::Ready
            || self.fifo.state() != super::fifo::State::Ready
        {
            return Err(Error::Terminal);
        }
        self.state = State::Terminal;
        let command = self.command()?;
        if command & (narf_bus::pci::cmd::BUS_MASTER | narf_bus::pci::cmd::MEM_SPACE)
            != narf_bus::pci::cmd::MEM_SPACE
        {
            return Err(Error::Busy);
        }
        let index = self
            .io
            .read32(self.regs.idx as u32)
            .map_err(|_| Error::Access)?;
        if index == u32::MAX || index & 0x0fff_0fff != 0 {
            return Err(Error::BadIndex);
        }
        super::download_dma::prepare(&mut self.io, self.chip).map_err(|_| Error::Access)?;
        crate::rtw88::pci_park::invoke(&self.authority, || {
            narf_bus::pci::set_command(
                &self.authority,
                &self.device,
                narf_bus::pci::cmd::BUS_MASTER,
            )?;
            narf_bus::pci::read_command(&self.authority, &self.device)
        })
        .map_err(|_| Error::Access)?
        .map_err(|_| Error::Access)?;
        if self.command()? & (narf_bus::pci::cmd::BUS_MASTER | narf_bus::pci::cmd::MEM_SPACE)
            != (narf_bus::pci::cmd::BUS_MASTER | narf_bus::pci::cmd::MEM_SPACE)
        {
            return Err(Error::Access);
        }
        self.activate_registers()
    }
    /// Same native cold/MAC owner, with fresh private RX buffers. This does
    /// not enable any packet TX channel, PCI interrupt, radio or station.
    /// # Safety
    /// The enclosing Startup attempt retains/terminalizes all DMA on error or
    /// cancellation and excludes independent reset/PHY/IRQ/packet producers.
    pub(super) async unsafe fn prepare_receive(
        &mut self,
        mac: &super::mac_runtime::Mac,
    ) -> Result<(), super::rx_dma::Error> {
        use super::{power::Error as RegisterError, rx_dma::Error as ReceiveError};
        if self.state != State::Active
            || self.chip != ChipId::Rtl8852B
            || mac.state() != super::mac_runtime::State::Ready
            || self.identity().is_none()
        {
            return Err(ReceiveError::Register(RegisterError::Unsupported));
        }
        let command = self
            .command()
            .map_err(|_| ReceiveError::Register(RegisterError::Access))?;
        if command & (narf_bus::pci::cmd::BUS_MASTER | narf_bus::pci::cmd::MEM_SPACE)
            != (narf_bus::pci::cmd::BUS_MASTER | narf_bus::pci::cmd::MEM_SPACE)
        {
            return Err(ReceiveError::Register(RegisterError::Access));
        }
        let mut access = super::pcie_native::Native {
            io: &mut self.io,
            device: &self.device,
            authority: &self.authority,
        };
        // SAFETY: retained exact cold/MAC owner above; every RX allocation is
        // stored in self before publication and survives the outer attempt.
        unsafe { self.receive.prepare(&mut access, 64).await }
    }
    pub(super) fn poll_receive(
        &mut self,
        budget: usize,
    ) -> Result<alloc::vec::Vec<super::rx_packet::Event>, super::rx_dma::Error> {
        if self.state != State::Active {
            return Err(super::rx_dma::Error::Terminal);
        }
        let result = self.receive.poll(&mut self.io, budget);
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn radio_access(&self) -> Result<(), super::power::Error> {
        if self.state != State::Active
            || self.chip != ChipId::Rtl8852B
            || self.receive.state() != super::rx_dma::State::Polling
            || self.factory.as_ref().is_none_or(|f| f.b_phycap().is_none())
        {
            return Err(super::power::Error::Unsupported);
        }
        self.io.b_phy_window()
    }
    /// # Safety
    /// Enclosing composed radio attempt excludes reset/PHY/channel operations
    /// and terminalizes this same Native on failure or cancellation.
    pub(super) async unsafe fn read_rf(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
    ) -> Result<u32, super::power::Error> {
        self.radio_access()?;
        // SAFETY: actual cold/MAC/RX owner and complete current B PHY aperture
        // above; the enclosing retained radio attempt handles cancellation.
        let result = unsafe { self.radio.read(&mut self.io, path, address, mask).await };
        if result.is_err() {
            self.fail();
        }
        result
    }
    /// # Safety
    /// Same serialized retained radio-attempt contract as read_rf.
    pub(super) async unsafe fn write_rf(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), super::power::Error> {
        self.radio_access()?;
        // SAFETY: same actual full-aperture/current B radio owner; no parallel
        // producer and outer attempt retains DMA on failure/cancellation.
        let result = unsafe {
            self.radio
                .write(&mut self.io, path, address, mask, value)
                .await
        };
        if result.is_err() {
            self.fail();
        }
        result
    }
    /// Best-effort closure only. All published DMA remains retained because
    /// register stop/BME-off alone does not prove posted transactions drained.
    pub(super) fn fail(&mut self) {
        self.state = State::Terminal;
        self.receive.fail();
        if let Ok(value) = self.io.read32(0x1010) {
            if value != u32::MAX {
                let tx = if matches!(self.chip, ChipId::Rtl8852A | ChipId::Rtl8852C) {
                    0x7ff00
                } else {
                    0x70f00
                };
                let _ = self.io.write32(0x1010, value | tx | (1 << 19) | 3);
            }
        }
        let mask = if self.chip == ChipId::Rtl8852C {
            (1 << 15) | (1 << 7)
        } else {
            (1 << 13) | (1 << 11)
        };
        if let Ok(value) = self.io.read32(0x1000) {
            if value != u32::MAX {
                let _ = self.io.write32(0x1000, value & !mask);
            }
        }
        let hci = if self.chip == ChipId::Rtl8852C {
            0x7880
        } else {
            0x8380
        };
        if let Ok(value) = self.io.read32(hci) {
            if value != u32::MAX {
                let _ = self.io.write32(hci, value & !3);
            }
        }
        let _ = crate::rtw88::pci_park::invoke(&self.authority, || {
            narf_bus::pci::clear_command(
                &self.authority,
                &self.device,
                narf_bus::pci::cmd::BUS_MASTER,
            )
        });
    }
    fn command(&self) -> Result<u16, Error> {
        crate::rtw88::pci_park::invoke(&self.authority, || {
            narf_bus::pci::read_command(&self.authority, &self.device)
        })
        .map_err(|_| Error::Access)?
        .map_err(|_| Error::Access)
    }
    /// Prepare the device's internal BD-RAM and zero hardware indices before
    /// any system-memory descriptor base is published.
    ///
    /// # Safety
    /// Same independently fenced, powered, exclusive device contract as new.
    /// Qualified platform quirks must already be known;
    /// `ber` carries the exact platform PCI_BER quirk. This composes DLFW
    /// DLE/HFC, AX PCIe pre-init and stopped BDRAM/mode preparation, but does
    /// includes retained PCI basic_cfg and does not establish DMA readiness.
    pub async unsafe fn prepare_bdram(&mut self, ber: bool) -> Result<(), Error> {
        if self.state != State::Unpublished
            || self.bdram.state() != super::bdram::State::New
            || self.pcie.state() != super::pcie::State::New
            || self.fifo.state() != super::fifo::State::New
            || self.basic.state() == super::pci_basic::State::Preparing
        {
            return Err(Error::Terminal);
        }
        match self.command() {
            Ok(command)
                if command & narf_bus::pci::cmd::BUS_MASTER == 0
                    && command & narf_bus::pci::cmd::MEM_SPACE != 0 => {}
            _ => {
                self.state = State::Terminal;
                self.bdram = super::bdram::Bdram::terminal();
                return Err(Error::Access);
            }
        }
        // SAFETY: caller's retained reset/serialization contract and the live
        // PCI command check above. NativeIo invokes authority for every MMIO.
        let result = async {
            if self.basic.state() == super::pci_basic::State::New {
                let mut access = super::pcie_native::Native {
                    io: &mut self.io,
                    device: &self.device,
                    authority: &self.authority,
                };
                // SAFETY: same function, independently fenced old DMA and live
                // BME-off command proof above; no producer or PM/reset owner.
                unsafe {
                    self.basic.prepare(&mut access, self.chip).await?;
                }
            }
            // SAFETY: retained fenced, powered, BME-off exclusive device.
            unsafe {
                self.fifo.prepare(&mut self.io, self.chip).await?;
            }
            let mut access = super::pcie_native::Native {
                io: &mut self.io,
                device: &self.device,
                authority: &self.authority,
            };
            // SAFETY: same exclusive device, current authority per transaction.
            unsafe {
                self.pcie
                    .prepare(&mut access, self.chip, self.cut, ber)
                    .await?;
            }
            // SAFETY: no ring or BME publication; exact mode follows idle/zero.
            unsafe {
                self.bdram
                    .prepare_with_mode(&mut self.io, self.chip, self.cut)
                    .await
            }
        }
        .await
        .map_err(|error| match error {
            super::power::Error::Timeout => Error::Timeout,
            super::power::Error::Unsupported => Error::Unsupported,
            super::power::Error::Terminal => Error::Terminal,
            _ => Error::Access,
        });
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
    /// # Safety
    /// Same stopped/fenced/serialized contract as new; BDRAM and hardware
    /// indices were prepared by this owner's prepare_bdram, with CH12 DMA
    /// disabled and the rest of the PCIe setup still retained.
    pub unsafe fn configure(&mut self) -> Result<(), Error> {
        if self.state != State::Unpublished
            || self.bdram.state() != super::bdram::State::Ready
            || self.pcie.state() != super::pcie::State::Ready
            || self.fifo.state() != super::fifo::State::Ready
            || self.basic.state() != super::pci_basic::State::Ready
        {
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
    pub fn chip(&self) -> ChipId {
        self.chip
    }
    pub fn firmware_prepared(&self) -> bool {
        self.state == State::Active && self.queue.is_pristine()
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
            DEVICE_DMA_MASK,
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
            self.fail();
            if let Some(ring) = self.ring.take() {
                core::mem::forget(ring);
            }
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "command_native_tests.rs"]
mod tests;
