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
#[path = "command_native/phycap.rs"]
mod phycap;
#[path = "command_native/radio.rs"]
mod radio;
#[path = "command_native/radio_51.rs"]
mod radio_51;
pub(in crate::rtw89) use radio::{c_profile, SixGhzChannel};
#[cfg(any(test, feature = "kernel-test"))]
pub(in crate::rtw89) use radio::{wide_profiles, wide_profiles_c160};
#[path = "command_native/rf_tracking.rs"]
mod rf_tracking;
pub(super) use radio::{QualificationRequest, RadioPreflight};
#[path = "command_native/fragment.rs"]
mod fragment;
pub(super) use fragment::{
    Binding as FragmentBinding, Part as FragmentPart, Train as FragmentTrain,
};
#[path = "command_native/ap.rs"]
mod ap;
#[path = "command_native/lps.rs"]
mod lps;
#[path = "command_native/monitor.rs"]
mod monitor;
#[path = "command_native/station.rs"]
mod station;
#[path = "command_native/wow.rs"]
mod wow;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Unpublished,
    Configuring,
    Configured,
    Active,
    Terminal,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CalibrationError {
    Policy(super::calibration_policy::Error),
    Coex(super::coex_native::Error),
    Radio(super::radio_init::Error),
    Rfk(super::rfk::Error),
    Register(super::power::Error),
    Profile,
}
/// Pure staging result bound to the retained actual factory and assets. It
/// grants no hardware readiness and is consumed by one later radio attempt.
pub(super) struct BasicPreflight {
    board: super::calibration_policy::Board,
    calibration: super::calibration_policy::Calibration,
    protocol: super::coex_native::Protocol,
}
/// Sealed ordinary RF/response receipt. No value can be constructed while
/// full BB/channel/IQK/TSSI/DPK/source-power qualification is incomplete.
/// Basic calibration and DMA receipts cannot be converted into this type.
///
/// Chip-dispatched: RTL8852B holds the signed `N52B` v2 full program (with
/// its WMM/QoS/RA/HT/HE/A-MPDU/sleep/fragment companions); RTL8852C holds
/// the signed `N5CB` v2 + `N5CC` program, which carries no such companion.
/// B-only program accessors ([`Self::b`]) therefore see "no program" on C.
/// RTL8851B holds the signed `N51B` v2 + `N51C` program
/// (`radio_policy_51`), likewise without a B companion.
#[derive(Clone)]
enum OrdinaryGrant {
    B(alloc::sync::Arc<super::radio_policy::Qualification>),
    C(alloc::sync::Arc<super::radio_policy_c::Qualification>),
    N51(alloc::sync::Arc<super::radio_policy_51::Qualification>),
}
impl OrdinaryGrant {
    fn current(&self) -> Result<(), super::power::Error> {
        match self {
            Self::B(q) => q.current().map_err(|_| super::power::Error::Access),
            Self::C(q) => q.current().map_err(|_| super::power::Error::Access),
            Self::N51(q) => q.current().map_err(|_| super::power::Error::Access),
        }
    }
    /// Keep actual publication inside the chip's exact signed invocation.
    fn with_current<T>(
        &self,
        operation: impl FnOnce() -> Result<T, super::power::Error>,
    ) -> Result<T, super::power::Error> {
        match self {
            Self::B(q) => q.with_current(operation),
            Self::C(q) => q.with_current(operation),
            Self::N51(q) => q.with_current(operation),
        }
    }
    /// The RTL8852B program and its companions; `None` ("no program") on C
    /// and RTL8851B.
    fn b(&self) -> Option<&alloc::sync::Arc<super::radio_policy::Qualification>> {
        match self {
            Self::B(q) => Some(q),
            Self::C(_) | Self::N51(_) => None,
        }
    }
}
/// Band-qualified identity of the programmed operating channel (mac80211
/// `cfg80211_chan_def.chan`: band + channel number). A bare primary number
/// cannot name a 6GHz channel (6GHz 1/5/9/13 collide with 2.4GHz), so the
/// native owner records the band the program was built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct OperatingChannel {
    band: super::operating_channel_c::Band,
    primary: u8,
}
impl OperatingChannel {
    pub(in crate::rtw89) const fn new(band: super::operating_channel_c::Band, primary: u8) -> Self {
        Self { band, primary }
    }
    /// The RTL8852B / 2.4+5GHz numbering: 1..=14 is 2.4GHz, every other
    /// primary 5GHz (6GHz is never named by a bare primary).
    pub(in crate::rtw89) const fn legacy(primary: u8) -> Self {
        let band = if primary <= 14 {
            super::operating_channel_c::Band::Ghz2
        } else {
            super::operating_channel_c::Band::Ghz5
        };
        Self { band, primary }
    }
    pub(in crate::rtw89) const fn band(self) -> super::operating_channel_c::Band {
        self.band
    }
    pub(in crate::rtw89) const fn primary(self) -> u8 {
        self.primary
    }
    /// No CCK on this band (5/6GHz): core.c `rtw89_core_get_mgmt_rate`
    /// floors at `RTW89_HW_RATE_OFDM6` off 2.4GHz.
    pub(in crate::rtw89) const fn ofdm_only(self) -> bool {
        !matches!(self.band, super::operating_channel_c::Band::Ghz2)
    }
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
    runtime_sequence: u16,
    station_runtime: station::Runtime,
    sleep_blocked: bool,
    sleep_reset: Option<super::pci_reset::Reset<super::pci_reset::Native>>,
    calibration: Option<super::calibration_policy::Calibration>,
    coex_ready: bool,
    nctl_ready: bool,
    calibrating: Option<super::rfk::Kind>,
    scheduler: Option<super::scheduler_mailbox::Mailbox>,
    phycap: Option<super::firmware_phycap::Receipt>,
    phycap_attempted: bool,
    gain_bases: Option<[i8; 2]>,
    radio_started: bool,
    radio_shutdown: super::radio_shutdown::Shutdown,
    ordinary: Option<OrdinaryGrant>,
    full_qualification: Option<alloc::sync::Arc<super::radio_policy::Qualification>>,
    /// RTL8852C signed full program (N5CB v2 + N5CC records) gating every
    /// C radio access together with the C calibration record.
    qualification_c: Option<alloc::sync::Arc<super::radio_policy_c::Qualification>>,
    /// RTL8851B signed full program (N51B v2 + N51C records) gating every
    /// RTL8851B radio access together with the N51B calibration record.
    qualification_51: Option<alloc::sync::Arc<super::radio_policy_51::Qualification>>,
    operating: Option<super::phy_operating::Operating>,
    irq: Option<super::irq::Binding>,
    /// RTL8852B HCI DMA-stop proof earned by the terminal closure.
    dma_idle: Option<super::dma_stop::Idle>,
    /// Every published ring, buffer and packet was released after the proof.
    dma_reclaimed: bool,
    /// Observed-FLR lifecycle that selects the signed radio identity.
    lifecycle: super::radio_policy::Lifecycle,
    /// Band-qualified channel and retune epoch of the completed full
    /// program; cleared while a retune runs. Consumers compare the epoch
    /// they were built against.
    channel: Option<(OperatingChannel, u32)>,
    /// Open reversible WoW TRX window (`command_native/wow.rs`).
    wow_trx: Option<wow::Trx>,
}
/// Current-authority BAR/config adapter for the DMA-stop proof.
struct StopPort<'a> {
    io: &'a mut NativeIo,
    device: &'a BusDevice,
    authority: &'a Cap<BusDeviceCap, Write>,
}
impl super::dma_stop::Port for StopPort<'_> {
    fn read32(&mut self, address: u32) -> Result<u32, super::power::Error> {
        super::power::Io::read32(self.io, address)
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), super::power::Error> {
        super::power::Io::write32(self.io, address, value)
    }
    fn bus_master(&mut self) -> Result<bool, super::power::Error> {
        let command = crate::rtw88::pci_park::invoke(self.authority, || {
            narf_bus::pci::read_command(self.authority, self.device)
        })
        .map_err(|_| super::power::Error::Access)?
        .map_err(|_| super::power::Error::Access)?;
        if command == u16::MAX {
            return Err(super::power::Error::Gone);
        }
        Ok(command & narf_bus::pci::cmd::BUS_MASTER != 0)
    }
    fn clear_bus_master(&mut self) -> Result<(), super::power::Error> {
        crate::rtw88::pci_park::invoke(self.authority, || {
            narf_bus::pci::clear_command(
                self.authority,
                self.device,
                narf_bus::pci::cmd::BUS_MASTER,
            )
        })
        .map_err(|_| super::power::Error::Access)?
        .map_err(|_| super::power::Error::Access)
        .map(|_| ())
    }
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
            runtime_sequence: 0,
            station_runtime: station::Runtime::default(),
            sleep_blocked: false,
            sleep_reset: None,
            calibration: None,
            coex_ready: false,
            nctl_ready: false,
            calibrating: None,
            scheduler: Some(super::scheduler_mailbox::Mailbox::for_chip(chip)),
            phycap: None,
            phycap_attempted: false,
            dma_idle: None,
            dma_reclaimed: false,
            lifecycle: super::radio_policy::Lifecycle::Initial,
            channel: None,
            wow_trx: None,
            gain_bases: None,
            radio_started: false,
            radio_shutdown: super::radio_shutdown::Shutdown::default(),
            ordinary: None,
            full_qualification: None,
            qualification_c: None,
            qualification_51: None,
            operating: Some(super::phy_operating::Operating::default()),
            irq: None,
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
        // B, C or RTL8851B, each with its own completed factory PHY-cap
        // window; the chip-specific MAC branches live in `mac_runtime` (C:
        // `mac_runtime/c.rs`; RTL8851B: the B sequence's `n51` branches).
        let phycap = self
            .factory
            .as_ref()
            .is_some_and(|factory| match self.chip {
                ChipId::Rtl8852B => factory.b_phycap().is_some(),
                ChipId::Rtl8852C => factory.c_phycap().is_some(),
                ChipId::Rtl8851B => factory.n51_phycap().is_some(),
                _ => false,
            });
        if self.state != State::Active || !phycap {
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
            || !matches!(
                self.chip,
                ChipId::Rtl8852B | ChipId::Rtl8852C | ChipId::Rtl8851B
            )
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
        // C uses its own HAXI/V1 RX geometry (rx_dma::Rx::prepare_for).
        unsafe { self.receive.prepare_for(&mut access, self.chip, 64).await }
    }
    pub(super) fn poll_receive(
        &mut self,
        budget: usize,
    ) -> Result<alloc::vec::Vec<super::rx_packet::Event>, super::rx_dma::Error> {
        if self.state != State::Active {
            return Err(super::rx_dma::Error::Terminal);
        }
        let authority = self.authority;
        let result =
            crate::rtw88::pci_park::invoke(&authority, || self.receive.poll(&mut self.io, budget))
                .map_err(|_| super::rx_dma::Error::Register(super::power::Error::Access))
                .and_then(|result| result);
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn radio_access(&mut self) -> Result<(), super::power::Error> {
        // Chip dispatch: B, C or RTL8851B with its own factory PHY-cap and
        // window.
        let phycap = match self.chip {
            ChipId::Rtl8851B => self
                .factory
                .as_ref()
                .is_some_and(|f| f.n51_phycap().is_some()),
            ChipId::Rtl8852B => self
                .factory
                .as_ref()
                .is_some_and(|f| f.b_phycap().is_some()),
            ChipId::Rtl8852C => self
                .factory
                .as_ref()
                .is_some_and(|f| f.c_phycap().is_some()),
            _ => false,
        };
        if self.state != State::Active
            || !phycap
            || self.receive.state() != super::rx_dma::State::Polling
        {
            return Err(super::power::Error::Unsupported);
        }
        match self.chip {
            ChipId::Rtl8852C => self.io.c_phy_window()?,
            ChipId::Rtl8851B => self.io.n51_phy_window()?,
            _ => self.io.b_phy_window()?,
        }
        let functions = self.io.read32(0xc000)?;
        if functions == u32::MAX || functions & (1 << 29) != 0 {
            return Err(super::power::Error::Access);
        }
        Ok(())
    }
    fn calibration_access(&mut self) -> Result<(), super::power::Error> {
        if let Some(c) = self.qualification_c.as_ref() {
            c.current().map_err(|_| super::power::Error::Access)?;
        }
        if let Some(n51) = self.qualification_51.as_ref() {
            n51.current().map_err(|_| super::power::Error::Access)?;
        }
        if let Some(full) = self.full_radio_scope() {
            full.current().map_err(|_| super::power::Error::Access)?;
        } else {
            self.calibration
                .as_ref()
                .ok_or(super::power::Error::Access)?
                .current()
                .map_err(|_| super::power::Error::Access)?;
        }
        self.radio_access()
    }
    /// Packet/control adapters must call this at actual RF publication. The
    /// sealed full-radio grant is absent until its source recipe is complete;
    /// no public boolean or basic-calibration receipt opens ordinary TX/ACK.
    pub(super) fn ordinary_current(&self) -> Result<(), super::power::Error> {
        if self.state != State::Active {
            return Err(super::power::Error::Terminal);
        }
        self.ordinary
            .as_ref()
            .ok_or(super::power::Error::Unsupported)?
            .current()
    }
    /// Execute actual ordinary publication inside both the actual device and
    /// signed measured RF capability invocations, with fresh host policy.
    pub(super) fn with_ordinary_current<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, super::power::Error>,
    ) -> Result<T, super::power::Error> {
        if self.state != State::Active {
            return Err(super::power::Error::Terminal);
        }
        let grant = self
            .ordinary
            .as_ref()
            .ok_or(super::power::Error::Unsupported)?
            .clone();
        let authority = self.authority;
        crate::rtw88::pci_park::invoke(&authority, || {
            grant.with_current(|| {
                if self.state != State::Active {
                    return Err(super::power::Error::Terminal);
                }
                operation(self)
            })
        })
        .map_err(|_| super::power::Error::Access)?
    }
    fn register_access(&self) -> Result<(), super::power::Error> {
        if self.state != State::Active {
            return Err(super::power::Error::Terminal);
        }
        if let Some(full) = self.full_radio_scope() {
            full.current().map_err(|_| super::power::Error::Access)?;
        } else if let Some(basic) = self.calibration.as_ref() {
            basic.current().map_err(|_| super::power::Error::Access)?;
        }
        Ok(())
    }
    fn command_admission(&mut self) -> Result<(), Error> {
        if self.register_access().is_err() {
            self.state = State::Terminal;
            return Err(Error::Access);
        }
        Ok(())
    }
    pub(super) fn preflight_basic_rfk(
        &self,
        assets: &super::radio_assets::Assets,
    ) -> Result<BasicPreflight, CalibrationError> {
        use CalibrationError as E;
        crate::rtw88::pci_park::invoke(&self.authority, || {
            if self.state != State::Active
                || self.chip != ChipId::Rtl8852B
                || self.receive.state() != super::rx_dma::State::Polling
            {
                return Err(E::Profile);
            }
            self.phy_profile_current().map_err(E::Register)?;
            let factory = self.factory.as_ref().ok_or(E::Profile)?;
            let board = super::calibration_policy::Board::new(factory, self.device.id, assets)
                .map_err(E::Policy)?;
            let protocol = super::coex_native::Protocol::for_version(assets.firmware_version())
                .ok_or(E::Profile)?;
            let calibration =
                super::calibration_policy::Calibration::load(board).map_err(E::Policy)?;
            calibration.current().map_err(E::Policy)?;
            Ok(BasicPreflight {
                board,
                calibration,
                protocol,
            })
        })
        .map_err(|_| E::Register(super::power::Error::Access))?
    }
    /// # Safety
    /// Same retained Startup, completed actual tables and exclusive radio
    /// ownership. Cancellation/failure terminalizes this Native and retains
    /// all possibly referenced DMA. This is calibration only, not TX admission.
    pub(super) async unsafe fn prepare_basic_rfk(
        &mut self,
        tables: &super::radio_init::Init,
        assets: &super::radio_assets::Assets,
        coex: &mut super::coex_native::Coex,
        rfk: &mut super::rfk::Rfk,
        preflight: BasicPreflight,
    ) -> Result<(), CalibrationError> {
        use CalibrationError as E;
        self.phy_profile_current().map_err(E::Register)?;
        self.radio_access().map_err(E::Register)?;
        if tables.state() != super::radio_init::State::TablesLoaded
            || self.calibration.is_some()
            || self.coex_ready
            || self.nctl_ready
            || rfk.state() != super::rfk::State::New
        {
            return Err(E::Profile);
        }
        let factory = self.factory.as_ref().ok_or(E::Profile)?;
        let identity = factory.identity().ok_or(E::Profile)?;
        let board = super::calibration_policy::Board::new(factory, self.device.id, assets)
            .map_err(E::Policy)?;
        if preflight.board != board || !preflight.calibration.matches(board) {
            return Err(E::Profile);
        }
        preflight.calibration.current().map_err(E::Policy)?;
        let protocol = preflight.protocol;
        let rfe = identity.calibration().rfe_type;
        let cut = identity.cut();
        self.calibration = Some(preflight.calibration);
        // SAFETY: actual current signed measured calibration envelope above,
        // same retained exact factory/B radio backend and CMAC TX closed.
        unsafe { coex.prepare(self, rfe, cut, protocol).await }.map_err(E::Coex)?;
        self.coex_ready = true;
        // Exact bb_sethw prefix; full channel/CCA/TRX controls remain later.
        self.gain_bases = Some(super::radio_init::controls(self).map_err(E::Radio)?);
        let mut operating = self.operating.take().ok_or(E::Profile)?;
        // SAFETY: actual retained factory identity, current signed basic recipe,
        // real firmware PHY/coexistence ownership; no NCTL calibration starts
        // before these source static operating controls have completed.
        let result = unsafe { operating.prepare(self, identity).await };
        self.operating = Some(operating);
        result.map_err(E::Rfk)?;

        let nctl = super::radio_table::program(assets.table(4).ok_or(E::Profile)?, rfe, cut)
            .map_err(|_| E::Profile)?;
        super::radio_init::nctl(self, &nctl)
            .await
            .map_err(E::Radio)?;
        self.nctl_ready = true;
        // SAFETY: actual NCTL, source WLAN-only owner and currently valid
        // measured recipe/channel policy are retained on this same Native.
        unsafe { rfk.prepare(self).await }.map_err(E::Rfk)
    }
    /// # Safety
    /// Same retained Startup radio attempt; cancellation closes this Native
    /// while keeping every published DMA mapping and quarantine alive.
    pub(super) async unsafe fn prepare_radio_tables(
        &mut self,
        owner: &mut super::radio_init::Init,
        assets: &super::radio_assets::Assets,
    ) -> Result<(), super::radio_init::Error> {
        self.radio_profile_current()?;
        self.radio_access()?;
        let factory = self
            .factory
            .as_ref()
            .ok_or(super::radio_init::Error::Profile)?;
        // Chip dispatch: B, C or RTL8851B tables from the matching factory
        // snapshot.
        let qualified = match self.chip {
            ChipId::Rtl8852C => super::radio_init::Qualified::from_factory_c(factory),
            ChipId::Rtl8851B => super::radio_init::Qualified::from_factory_51(factory),
            _ => super::radio_init::Qualified::from_factory(factory),
        }
        .ok_or(super::radio_init::Error::Profile)?;
        // Latch before the first possible BB/RF write; cancellation cannot
        // hide independent PMAC/NCTL state from terminal emission closure.
        self.radio_started = true;
        // SAFETY: actual factory, MAC/RX backend and full current B aperture
        // above; outer retained Startup attempt handles cancellation/failure.
        unsafe { owner.prepare(self, qualified, assets).await }
    }
    async fn upload_radio_page(
        &mut self,
        path: u8,
        page: u8,
        bytes: &[u8],
    ) -> Result<(), super::radio_init::Error> {
        self.radio_profile_current()?;
        self.radio_access()?;
        self.transmit_radio_page(path, page, bytes).await
    }
    fn radio_page_packet(
        &mut self,
        path: u8,
        page: u8,
        bytes: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, super::radio_init::Error> {
        use super::radio_init::Error as RadioError;
        if path > 1
            || page >= 3
            || bytes.is_empty()
            || bytes.len() > 2000
            || bytes.len() % 4 != 0
            || self.runtime_sequence >= 256
        {
            return Err(RadioError::Profile);
        }
        let sequence = self.runtime_sequence as u8;
        // No sequence reuse within this one-shot initial profile, including
        // failed/ambiguous publication. Future station commands share it.
        self.runtime_sequence += 1;
        let mut packet = alloc::vec![0;8+bytes.len()];
        super::txrx::encode_h2c_header(
            2,
            8 + path,
            page,
            sequence,
            bytes.len() as u16,
            sequence % 4 == 0,
            false,
            &mut packet,
        )
        .ok_or(RadioError::Profile)?;
        packet[8..].copy_from_slice(bytes);
        Ok(packet)
    }
    async fn transmit_radio_page(
        &mut self,
        path: u8,
        page: u8,
        bytes: &[u8],
    ) -> Result<(), super::radio_init::Error> {
        use super::radio_init::Error as RadioError;
        let packet = self.radio_page_packet(path, page, bytes)?;
        self.send(Kind::Header, &packet)
            .await
            .map_err(|_| RadioError::Register(super::power::Error::Access))?;
        let start = self.io.now_us();
        loop {
            self.poll()
                .map_err(|_| RadioError::Register(super::power::Error::Access))?;
            if self.queue.pending() == 0 {
                return Ok(());
            }
            if self.io.now_us().saturating_sub(start) >= 400_000 {
                return Err(super::power::Error::Timeout.into());
            }
            self.io.delay_us(50).await;
        }
    }
    /// Serialized ordinary runtime command; source DONE_ACK means execution,
    /// while CH12 RP retirement proves only descriptor consumption. Every ACK
    /// identity and status must match this never-reused runtime sequence.
    async fn coex_command(
        &mut self,
        function: u8,
        bytes: &[u8],
        done: bool,
    ) -> Result<(), super::coex_native::Error> {
        self.calibration_access()
            .map_err(super::coex_native::Error::Register)?;
        self.runtime_command(2, 0x10, function, bytes, done, station::Permit::Legacy)
            .await
            .map_err(super::coex_native::Error::Register)
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
        let full = self.full_radio_scope();
        let chip = self.chip_program();
        let mut io = radio::Port::new(&mut self.io, self.calibration.as_ref(), full, chip);
        // SAFETY: actual cold/MAC/RX owner, complete B aperture and current
        // signed register scope; retained outer attempt handles cancellation.
        let result = unsafe { self.radio.read(&mut io, path, address, mask).await };
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
        if self.station_runtime.monitor.is_some() {
            return Err(super::power::Error::Unsupported);
        }
        self.radio_access()?;
        // SAFETY: same actual full-aperture/current B radio owner; no parallel
        // producer and outer attempt retains DMA on failure/cancellation.
        let full = self.full_radio_scope();
        let chip = self.chip_program();
        let mut io = radio::Port::new(&mut self.io, self.calibration.as_ref(), full, chip);
        // SAFETY: same retained analog owner with current signed MMIO scope.
        let result = unsafe { self.radio.write(&mut io, path, address, mask, value).await };
        if result.is_err() {
            self.fail();
        }
        result
    }
    /// Best-effort closure only. All published DMA remains retained because
    /// register stop/BME-off alone does not prove posted transactions drained.
    pub(super) fn fail(&mut self) {
        self.state = State::Terminal;
        if self.sleep_reset.is_some() {
            return;
        } // Never access during/after FLR quarantine.
          // rtw89_pci_ops_stop + free_irq: HIMR and MSI off before BME clears.
        self.irq_release();
        self.receive.fail();
        if self.sleep_blocked {
            // Clock-gated or interrupted PS work cannot borrow an ordinary
            // register stop as a wake/firmware-autonomy retirement proof.
            // Retained async cleanup takes the actual nonemitting FLR path.
            return;
        }
        // Autonomous ACK/CTS does not depend on a packet DMA doorbell.
        if let Ok(value) = self.io.read32(0xc000) {
            if !matches!(value, u32::MAX | 0xeaea_eaea) {
                let _ = self.io.write32(0xc000, value & !(1 << 29));
            }
        }
        if let Some(layout) = super::dma_stop::Layout::for_chip(self.chip) {
            // Linux stop/poll order with BME still on, then BME off and a
            // flushing re-read. An earlier proof already cleared BME.
            if self.dma_idle.is_none() && !self.dma_reclaimed {
                self.dma_idle = super::dma_stop::stop_with(&mut self.stop_port(), layout).ok();
            }
            // C shares the AX BB engine/clock closure registers (cr_base
            // 0x10000; rtw8852c_mac_disable_bb_rf is exactly `clocks`).
            if self.radio_started {
                let _ = super::radio_stop::engines(&mut self.io);
            }
            let _ = super::radio_stop::clocks(&mut self.io);
            return;
        }
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
        // rtw8851b.c `rtw8851b_mac_disable_bb_rf` is byte-identical to
        // `__rtw8852bx_mac_disable_bb_rf`, and RTL8851B shares the AX PMAC/
        // MAC_SEL/NCTL/KIP closure registers, so it takes B's closure.
        if matches!(self.chip, ChipId::Rtl8852B | ChipId::Rtl8851B) {
            if self.radio_started {
                let _ = super::radio_stop::engines(&mut self.io);
            }
            let _ = super::radio_stop::clocks(&mut self.io);
        }
    }
    /// Complete source RF00S/RF10S disable after immediate terminal closure.
    /// This never reopens the owner or grants DMA reclamation/reset authority.
    pub(super) async fn finish_radio_shutdown(&mut self) -> Result<(), super::power::Error> {
        if self.sleep_reset.is_some()
            || self.state != State::Terminal
            || !matches!(
                self.chip,
                ChipId::Rtl8852B | ChipId::Rtl8852C | ChipId::Rtl8851B
            )
        {
            return Err(super::power::Error::Terminal);
        }
        self.fail();
        // RTL8851B: rtw8851b.c `rtw8851b_mac_disable_bb_rf` is byte-identical
        // to `__rtw8852bx_mac_disable_bb_rf` (RF00S_EN at XTAL_SI_WL_RFC_S0
        // and RF10S_EN at S1 are both cleared even on the one-path chip), so
        // it takes B's `finish`.
        // SAFETY: same retained exclusively owned exact B/C function, closed
        // producers and uncertain DMA kept alive; NativeIo invokes current
        // device authority for every actual shutdown register transaction.
        unsafe {
            if self.chip == ChipId::Rtl8852C {
                self.radio_shutdown
                    .finish_c(&mut self.io, self.radio_started)
                    .await
            } else {
                self.radio_shutdown
                    .finish(&mut self.io, self.radio_started)
                    .await
            }
        }
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
        let authority = self.authority;
        let result = crate::rtw88::pci_park::invoke(&authority, || {
            let value = self
                .io
                .read32(self.regs.idx as u32)
                .map_err(|_| Error::Access)?;
            if value == u32::MAX {
                return Err(Error::Access);
            }
            barrier();
            let read = ((value >> 16) & 0xfff) as u16;
            let retired = self.queue.observe(read)?;
            let count = retired.len();
            drop(retired);
            Ok(count)
        })
        .map_err(|_| Error::Access)
        .and_then(|result| result);
        if result.is_err() {
            self.state = State::Terminal;
        }
        result
    }
    /// A successful return means publication, never firmware execution or DMA
    /// retirement. The retained queue owns every command throughout its wait.
    pub async fn send(&mut self, kind: Kind, bytes: &[u8]) -> Result<(), Error> {
        self.send_permit(kind, bytes, station::Permit::Legacy).await
    }
    fn stop_port(&mut self) -> StopPort<'_> {
        StopPort {
            io: &mut self.io,
            device: &self.device,
            authority: &self.authority,
        }
    }
    /// Release CH12, RXQ/RPQ and every TX ring/packet once the terminal
    /// closure earned `dma_stop::Idle`. The stopped/idle/BME-off state is
    /// re-verified under current authority first; any failure keeps all
    /// storage pinned for the boot. Returns the number of released buffers.
    pub(super) fn reclaim_dma(&mut self) -> Result<usize, super::dma_stop::Error> {
        if self.dma_reclaimed {
            return Ok(0);
        }
        if self.state != State::Terminal || self.irq.is_some() || self.dma_idle.is_none() {
            return Err(super::dma_stop::Error::Unproven);
        }
        let layout =
            super::dma_stop::Layout::for_chip(self.chip).ok_or(super::dma_stop::Error::Unproven)?;
        super::dma_stop::verify_with(&mut self.stop_port(), layout)?;
        let proof = self
            .dma_idle
            .take()
            .ok_or(super::dma_stop::Error::Unproven)?;
        Ok(self.release_proven(proof))
    }
    /// Consume the verified proof and free every published allocation.
    fn release_proven(&mut self, _proof: super::dma_stop::Idle) -> usize {
        // SAFETY: the consumed sealed current DMA idle proof covers this owner.
        unsafe { self.release_all_fenced() }
    }
    fn release_reset_fenced(
        &mut self,
        proof: super::pci_reset::Fence,
    ) -> Result<usize, super::power::Error> {
        if self.state != State::Terminal
            || self.irq.is_some()
            || self.sleep_reset.is_none()
            || !proof.matches_function(&self.device, &self.authority)
        {
            return Err(super::power::Error::Terminal);
        }
        // SAFETY: exact sealed successful temporal FLR fence, exclusive original
        // function, IRQ closed before quarantine, and no producer may restart.
        Ok(unsafe { self.release_all_fenced() })
    }
    /// # Safety
    /// A consumed actual same-function DMA idle or successful temporal FLR
    /// fence proves all published descriptor/prefetch references are gone.
    unsafe fn release_all_fenced(&mut self) -> usize {
        let mut released = 0;
        if let Some(core) = self.station_runtime.core.as_mut() {
            // SAFETY: proof above covers every TX channel and BME-off.
            released += unsafe { core.reclaim_fenced() }.len();
        }
        // SAFETY: the same proof covers RXQ/RPQ.
        released += unsafe { self.receive.reclaim_fenced() }.len();
        // SAFETY: CH12 is in the proof's TX stop/busy mask.
        unsafe {
            self.queue.reclaim_fenced();
        }
        released += usize::from(self.ring.take().is_some());
        self.armed = false;
        self.dma_reclaimed = true;
        released
    }
    /// Set by Startup from its reset fence before any radio identity use.
    pub(super) fn set_lifecycle(&mut self, lifecycle: super::radio_policy::Lifecycle) {
        self.lifecycle = lifecycle;
    }
    pub(super) fn dma_reclaimed(&self) -> bool {
        self.dma_reclaimed
    }
    /// Removal/re-initialization retirement: terminal closure (earning the
    /// stop proof on RTL8852B), then reclamation. True only when nothing
    /// this owner ever published remains pinned. CH12 is published before
    /// RXQ/RPQ or any TX ring, so an unarmed owner published nothing.
    pub(super) fn retire_dma(&mut self) -> bool {
        self.fail();
        self.dma_reclaimed || !self.armed || self.reclaim_dma().is_ok()
    }
    /// # Safety
    /// Hardware stop/idle and all DMA/prefetch fences are complete. Neither
    /// capability revocation nor BME-off establishes this reclamation proof.
    pub unsafe fn reclaim_fenced(&mut self) {
        // SAFETY: caller proves queued and multi-tag references are gone.
        unsafe {
            self.queue.reclaim_fenced();
        }
        self.armed = false;
        self.state = State::Terminal;
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        if self.armed || self.radio_started {
            self.fail();
            if self.armed && self.reclaim_dma().is_err() {
                if let Some(ring) = self.ring.take() {
                    core::mem::forget(ring);
                }
            }
        }
    }
}
impl super::power::Io for Native {
    fn read8(&mut self, a: u32) -> Result<u8, super::power::Error> {
        self.radio_io()?.read8(a)
    }
    fn read16(&mut self, a: u32) -> Result<u16, super::power::Error> {
        self.radio_io()?.read16(a)
    }
    fn read32(&mut self, a: u32) -> Result<u32, super::power::Error> {
        self.radio_io()?.read32(a)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), super::power::Error> {
        self.radio_io()?.write8(a, v)
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), super::power::Error> {
        self.radio_io()?.write16(a, v)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), super::power::Error> {
        self.radio_io()?.write32(a, v)
    }
    fn now_us(&self) -> u64 {
        self.io.now_us()
    }
    async fn delay_us(&mut self, us: u64) {
        self.io.delay_us(us).await;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, super::power::Error> {
        Err(super::power::Error::Unsupported)
    }
}
impl super::radio_init::Interface for Native {
    async fn radio_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), super::radio_init::Error> {
        // SAFETY: this private adapter is used by the same retained radio
        // preparation attempt, whose Drop closes/retains all native DMA.
        unsafe { self.write_rf(path, address, mask, value).await }.map_err(Into::into)
    }
    async fn radio_page(
        &mut self,
        path: u8,
        page: u8,
        bytes: &[u8],
    ) -> Result<(), super::radio_init::Error> {
        self.upload_radio_page(path, page, bytes).await
    }
}

impl Native {
    /// Chip dispatch of the WLAN-only `_set_ant(WONLY)` re-assertion: B
    /// `coex_native::enforce` unchanged, C `coex_native::enforce_c`.
    async fn coex_enforce(&mut self) -> Result<(), super::coex_native::Error> {
        if self.chip == ChipId::Rtl8852C {
            super::coex_native::enforce_c(self).await
        } else {
            super::coex_native::enforce(self).await
        }
    }
}
impl super::coex_native::Interface for Native {
    fn admit(&mut self) -> Result<(), super::coex_native::Error> {
        self.calibration_access().map_err(Into::into)
    }
    async fn rf_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), super::coex_native::Error> {
        self.calibration_access()?;
        // SAFETY: actual signed calibration admission above, same serialized
        // retained radio attempt and complete current-capability B aperture.
        unsafe { self.write_rf(path, address, mask, value).await }.map_err(Into::into)
    }
    async fn command(
        &mut self,
        function: u8,
        bytes: &[u8],
        done: bool,
    ) -> Result<(), super::coex_native::Error> {
        self.coex_command(function, bytes, done).await
    }
}
impl super::scheduler_mailbox::Interface for Native {
    fn admit(&mut self) -> Result<(), super::power::Error> {
        self.calibration_access()
    }
}
impl super::rfk::Interface for Native {
    fn admit(&mut self) -> Result<(), super::rfk::Error> {
        if !self.coex_ready || !self.nctl_ready {
            return Err(super::rfk::Error::Policy);
        }
        self.calibration_access().map_err(Into::into)
    }
    async fn rf_read(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
    ) -> Result<u32, super::rfk::Error> {
        super::rfk::Interface::admit(self)?;
        // SAFETY: retained exact current admitted NCTL/coexistence/RFK owner.
        unsafe { self.read_rf(path, address, mask).await }.map_err(Into::into)
    }
    async fn rf_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), super::rfk::Error> {
        super::rfk::Interface::admit(self)?;
        // SAFETY: same actual serialized qualified B calibration attempt.
        unsafe { self.write_rf(path, address, mask, value).await }.map_err(Into::into)
    }
    /// `_run_coex(BTC_RSN_NTFY_SWBAND)` with `dm->wl_only` set takes
    /// `_action_wl_only` before any band/link-mode dispatch:
    /// `_set_ant(FC_EXEC, BTC_ANT_WONLY)` is re-executed (actual grant
    /// writes with readback, `coex_native::enforce`) and
    /// `_set_policy(BTC_CXP_OFF_BT)` sends nothing because `_append_tdma`/
    /// `_append_slot` skip an unchanged TDMA/slot (policy_len 0). The
    /// band-specific `_action_wl_5g` (`BTC_ANT_FDD`, `OFF_EQ0`) is reached only
    /// without `wl_only`, which needs BT link state this owner never has.
    async fn coex_switch_band(&mut self) -> Result<(), super::rfk::Error> {
        super::rfk::Interface::admit(self)?;
        self.coex_enforce()
            .await
            .map_err(|_| super::rfk::Error::Policy)
    }
    async fn begin(&mut self, kind: super::rfk::Kind) -> Result<(), super::rfk::Error> {
        super::rfk::Interface::admit(self)?;
        // Linux _ntfy_wl_rfk returns immediately for IQK one-shot events:
        // only RFK_GO changes in software; the outer IQK retains arbitration.
        if kind == super::rfk::Kind::IqkPath {
            return if self.calibrating == Some(super::rfk::Kind::Iqk) {
                Ok(())
            } else {
                Err(super::rfk::Error::Terminal)
            };
        }
        if self.calibrating.is_some() {
            return Err(super::rfk::Error::Terminal);
        }
        self.calibrating = Some(kind);
        // Source TSSI has only type-IQK ONESHOT_START/STOP notifications.
        // These do not toggle the scoreboard or rerun coexistence.
        if kind == super::rfk::Kind::Tssi {
            return Ok(());
        }
        super::coex_native::scoreboard(self, 0x4803)
            .await
            .map_err(|_| super::rfk::Error::Policy)?;
        self.coex_enforce()
            .await
            .map_err(|_| super::rfk::Error::Policy)
    }
    async fn end(&mut self, kind: super::rfk::Kind) -> Result<(), super::rfk::Error> {
        super::rfk::Interface::admit(self)?;
        if kind == super::rfk::Kind::IqkPath {
            return if self.calibrating == Some(super::rfk::Kind::Iqk) {
                Ok(())
            } else {
                Err(super::rfk::Error::Terminal)
            };
        }
        if self.calibrating != Some(kind) {
            return Err(super::rfk::Error::Terminal);
        }
        if kind == super::rfk::Kind::Tssi {
            self.calibrating = None;
            return Ok(());
        }
        super::coex_native::scoreboard(self, 0x4003)
            .await
            .map_err(|_| super::rfk::Error::Policy)?;
        self.coex_enforce()
            .await
            .map_err(|_| super::rfk::Error::Policy)?;
        self.calibrating = None;
        Ok(())
    }
    async fn pause(&mut self) -> Result<u32, super::rfk::Error> {
        super::rfk::Interface::admit(self)?;
        let saved = self.io.read16(0xc348)?;
        let mut mailbox = self.scheduler.take().ok_or(super::rfk::Error::Terminal)?;
        let result = mailbox.scheduler(self, 0).await;
        self.scheduler = Some(mailbox);
        result?;
        Ok(u32::from(saved))
    }
    async fn resume(&mut self, saved: u32) -> Result<(), super::rfk::Error> {
        super::rfk::Interface::admit(self)?;
        let saved = u16::try_from(saved).map_err(|_| super::rfk::Error::Table)?;
        let mut mailbox = self.scheduler.take().ok_or(super::rfk::Error::Terminal)?;
        let result = mailbox.scheduler(self, saved).await;
        self.scheduler = Some(mailbox);
        result.map_err(Into::into)
    }
    /// One BE firmware-offload H2C (`H2C_CAT_OUTSRC` /
    /// `H2C_CL_OUTSRC_RF_FW_RFK`), sent like the C `RF_GET_MCCCH` H2C:
    /// no done-ack, `Permit::Legacy`. Unmatched C2H events (including
    /// the RFK report) are retained into the backlog by
    /// `runtime_command` for `await_rfk_report`.
    async fn h2c(
        &mut self,
        cat: u8,
        class: u8,
        func: u8,
        payload: &[u8],
    ) -> Result<(), super::rfk::Error> {
        super::rfk::Interface::admit(self)?;
        self.runtime_command(cat, class, func, payload, false, station::Permit::Legacy)
            .await
            .map_err(Into::into)
    }
    /// Wait for the firmware C2H RFK report (OUTSRC / RFK_REPORT /
    /// STATE), mirroring `wow_c2h`'s backlog poll: the retained backlog
    /// first (the report may already have arrived during the H2C
    /// send), then 50 us polls with RX steps until `timeout_ms`. A
    /// report that parses as a non-report message fails closed.
    async fn await_rfk_report(
        &mut self,
        timeout_ms: u64,
    ) -> Result<super::rfk::be_rfk::Report, super::rfk::Error> {
        super::rfk::Interface::admit(self)?;
        let start = self.io.now_us();
        loop {
            let index = self.station_runtime.backlog.iter().position(|event| {
                matches!(event, super::rx_packet::Event::Firmware(m)
                if (m.category, m.class, m.function)
                    == (
                        super::rfk::be_rfk::C2H_CAT_OUTSRC,
                        super::rfk::be_rfk::C2H_CLASS_RFK_REPORT,
                        super::rfk::be_rfk::C2H_FUNC_RFK_REPORT_STATE,
                    ))
            });
            if let Some(index) = index {
                if let Some(super::rx_packet::Event::Firmware(message)) =
                    self.station_runtime.backlog.remove(index)
                {
                    return super::rfk::be_rfk::parse_c2h_report(&message.bytes)
                        .ok_or(super::rfk::Error::Table);
                }
            }
            if self.io.now_us().saturating_sub(start) >= timeout_ms * 1000 {
                return Err(super::power::Error::Timeout.into());
            }
            self.io.delay_us(50).await;
            self.poll().map_err(|_| super::power::Error::Access)?;
            let batch = self
                .rx_hardware_step(32)
                .map_err(|_| super::power::Error::Access)?;
            for event in batch.events {
                self.retain_event(event)?;
            }
        }
    }
    /// `rtw89_btc_ntfy_wl_rfk` (`BTC_WRFKT_CHLK`): run coexistence
    /// with the current state, as `coex_switch_band` does. The WLRFK
    /// scoreboard bit (`BIT(11)`) is not written here: the tree's
    /// scoreboard helper overwrites the lower word instead of
    /// setting/clearing one bit.
    async fn coex_rfk(&mut self, _start: bool) -> Result<(), super::rfk::Error> {
        super::rfk::Interface::admit(self)?;
        self.coex_enforce()
            .await
            .map_err(|_| super::rfk::Error::Policy)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "command_native_tests.rs"]
pub(super) mod tests;
