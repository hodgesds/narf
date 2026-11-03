// SPDX-License-Identifier: GPL-2.0-or-later
//! Private PCI adapter transferred from the retained calibrated AR9285 owner.
use super::{
    identity,
    packet::{Error, Port},
};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
#[path = "packet_native/periodic.rs"]
mod live_calibration;
enum InstalledPower {
    Twenty([(u64, u32); 7]),
    Forty(super::calibration::wide::WideReport),
}
impl InstalledPower {
    fn registers(&self) -> &[(u64, u32)] {
        match self {
            Self::Twenty(powers) => powers,
            Self::Forty(actual) => &actual.powers.registers,
        }
    }
}
/// The calibrated chip this native owner was built from. The AR9285 report
/// carries the historical single-chain owner; AR9287 additionally retains
/// its signed board admission and MAC profile.
pub(super) enum Calibrated {
    Ar9285(super::calibration::Report),
    Ar9287 {
        report: super::calibration::ar9287::Report,
        grant: alloc::sync::Arc<super::admission::Grant>,
        profile: super::mac::Profile,
        /// Retained factory map for temperature compensation.
        image: alloc::boxed::Box<[u8]>,
    },
}
/// Raw BAR access for the AR9287 long calibration, only inside `access`.
struct LongCal<'a> {
    native: &'a Native,
    lost: bool,
}
impl super::identity::RegisterIo for LongCal<'_> {
    fn authorized(&self) -> bool {
        !self.lost
    }
    fn read32(&mut self, offset: u64) -> u32 {
        if self.lost || self.native.extent(offset).is_err() {
            self.lost = true;
            return u32::MAX;
        }
        // SAFETY: aligned, in-bounds BAR dword inside the current PCI and
        // physical-readback invocation of this sole native owner.
        unsafe { self.native.bar.read32(offset) }
    }
    fn write32(&mut self, offset: u64, value: u32) {
        if self.lost || self.native.extent(offset).is_err() {
            self.lost = true;
            return;
        }
        // SAFETY: same checked extent and current invocation as read32.
        unsafe { self.native.bar.write32(offset, value) }
    }
}
impl Calibrated {
    fn frequency_mhz(&self) -> u16 {
        match self {
            Self::Ar9285(report) => report.frequency_mhz,
            Self::Ar9287 { report, .. } => report.frequency_mhz,
        }
    }
    /// Current host permission for the calibrated program; AR9287 also
    /// re-proves its signed record and the signed ceiling under it.
    fn permitted(&self, domain: &narf_wireless::reg::RegulatoryDomain) -> bool {
        let Ok(permission) =
            super::calibration::Permission::from_domain_at(domain, self.frequency_mhz())
        else {
            return false;
        };
        match self {
            Self::Ar9285(report) => permission.allows_report(*report),
            Self::Ar9287 { report, grant, .. } => grant
                .invoke(|| Ok(grant.ceiling(permission.budget())))
                .is_ok_and(|ceiling| permission.allows_ar9287(report, ceiling)),
        }
    }
}
pub(super) struct Native {
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    bar: MmioRegion,
    active: AtomicBool,
    calibrated: Calibrated,
    channel_mask: u16,
    powers: Option<InstalledPower>,
    rf_silent: Option<(u8, bool)>,
    ht: narf_lib::sync::IrqSafeSpinLock<Option<alloc::sync::Arc<super::ht::Grant>>>,
    ht_facts: Option<super::ht::Facts>,
    ba: narf_lib::sync::IrqSafeSpinLock<Option<alloc::sync::Arc<super::rx_ba::Grant>>>,
    tx_ba: narf_lib::sync::IrqSafeSpinLock<Option<alloc::sync::Arc<super::tx_ba::Grant>>>,
    qos: narf_lib::sync::IrqSafeSpinLock<Option<alloc::sync::Arc<super::qos::Grant>>>,
    ps: narf_lib::sync::IrqSafeSpinLock<Option<alloc::sync::Arc<super::ps::Grant>>>,
    ps_bound: AtomicBool,
    ps_sleeping: AtomicBool,
    ps_failed: AtomicBool,
    periodic: narf_lib::sync::IrqSafeSpinLock<live_calibration::Slot>,
    msi: narf_lib::sync::IrqSafeSpinLock<Option<Msi>>,
}
/// Single MSI vector (Linux `ath9k_use_msi` + `pci_enable_msi`). The handler
/// only raises the retained signal; the BAR is serviced by the station task.
struct Msi {
    config: narf_bus::msi::MsiConfig,
    vector: u8,
    signal: alloc::sync::Arc<super::irq::Signal>,
}
/// Factory `rfSilent` (base header offset 20 in both the 4k and AR9287 maps):
/// GPIO input and polarity, never a guessed board output.
fn rf_silent(image: &[u8]) -> Result<Option<(u8, bool)>, Error> {
    let bytes = [image[20], image[21]];
    let rf = if image[7] & 1 != 0 {
        u16::from_be_bytes(bytes)
    } else {
        u16::from_le_bytes(bytes)
    };
    if rf & 1 == 0 {
        return Ok(None);
    }
    if rf & !31 != 0 {
        return Err(Error::Packet);
    }
    Ok(Some((((rf >> 2) & 7) as u8, rf & 2 != 0)))
}
static SIGNAL: narf_lib::sync::IrqSafeSpinLock<Option<alloc::sync::Arc<super::irq::Signal>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);
fn vector_irq(_cookie: u64) -> narf_interrupts::IrqStatus {
    let signal = { SIGNAL.lock().clone() };
    match signal {
        Some(signal) => {
            signal.raise();
            narf_interrupts::IrqStatus::Handled
        }
        None => narf_interrupts::IrqStatus::None,
    }
}
impl Native {
    /// # Safety
    /// Caller retains the sole AR9285 function and exact mapped BAR through
    /// calibration/MAC/packet composition. This adapter cannot be cloned.
    pub(super) unsafe fn new(
        device: BusDevice,
        cap: Cap<BusDeviceCap, Write>,
        bar: MmioRegion,
        report: super::calibration::Report,
        image: &[u8; super::EEPROM_4K_BYTES],
    ) -> Result<Self, Error> {
        // AR2427 shares this legacy owner; HT stays behind `ht::Facts`.
        if !crate::ath9k::ar9285_silicon(&device.id)
            || !(2412..=2472).contains(&report.frequency_mhz)
            || (report.frequency_mhz - 2412) % 5 != 0
        {
            return Err(Error::Packet);
        }
        let rf_silent = rf_silent(image)?;
        let mut channel_mask = 1 << ((report.frequency_mhz - 2412) / 5);
        for channel in 1..=13u16 {
            if super::phy::rates::checked_plan_at(image, 2407 + 5 * channel, 40).is_ok() {
                channel_mask |= 1 << (channel - 1);
            }
        }
        let powers = if report.frequency_mhz == 2412 {
            None
        } else {
            Some(InstalledPower::Twenty(
                super::phy::rates::checked_plan_at(
                    image,
                    report.frequency_mhz,
                    report.max_power_half_dbm,
                )
                .map_err(|_| Error::Packet)?
                .registers,
            ))
        };
        Ok(Self::assemble(
            device,
            cap,
            bar,
            Calibrated::Ar9285(report),
            channel_mask,
            powers,
            rf_silent,
        ))
    }
    fn assemble(
        device: BusDevice,
        cap: Cap<BusDeviceCap, Write>,
        bar: MmioRegion,
        calibrated: Calibrated,
        channel_mask: u16,
        powers: Option<InstalledPower>,
        rf_silent: Option<(u8, bool)>,
    ) -> Self {
        Self {
            device,
            cap,
            bar,
            active: AtomicBool::new(false),
            calibrated,
            channel_mask,
            powers,
            rf_silent,
            ht: narf_lib::sync::IrqSafeSpinLock::new(None),
            ht_facts: None,
            ba: narf_lib::sync::IrqSafeSpinLock::new(None),
            tx_ba: narf_lib::sync::IrqSafeSpinLock::new(None),
            qos: narf_lib::sync::IrqSafeSpinLock::new(None),
            ps: narf_lib::sync::IrqSafeSpinLock::new(None),
            ps_bound: AtomicBool::new(false),
            ps_sleeping: AtomicBool::new(false),
            ps_failed: AtomicBool::new(false),
            periodic: narf_lib::sync::IrqSafeSpinLock::new(live_calibration::Slot::default()),
            msi: narf_lib::sync::IrqSafeSpinLock::new(None),
        }
    }
    /// # Safety
    /// Same sole calibrated function as new(); this distinct constructor
    /// additionally consumes the actual fresh40 receipt and current H3 grant.
    pub(super) unsafe fn new_wide(
        device: BusDevice,
        cap: Cap<BusDeviceCap, Write>,
        bar: MmioRegion,
        image: &[u8; super::EEPROM_4K_BYTES],
        grant: alloc::sync::Arc<super::ht40::Grant>,
        actual: super::calibration::wide::WideReport,
    ) -> Result<Self, Error> {
        grant.accept(actual)?;
        // SAFETY: caller establishes the same exclusive native contract;
        // all40-specific ownership is installed before this object escapes.
        let mut native = unsafe { Self::new(device, cap, bar, actual.report, image) }?;
        native.powers = Some(InstalledPower::Forty(actual));
        *native.ht.lock() = Some(super::ht::Grant::from_wide(grant, actual)?);
        Ok(native)
    }
    /// # Safety
    /// Caller retains the sole AR9287 function and exact mapped BAR after
    /// `phy::ar9287::prepare` and `calibration::ar9287` ran under `grant`'s
    /// ceiling for `report`'s primary; no packet DMA was published.
    /// `channel_mask` (bit `n - 1` = channel `n`) names the channels whose
    /// signed per-channel `N87A` record and factory open-loop plan the owner
    /// verified; a cold retune re-loads the target record before retiring.
    #[allow(clippy::too_many_arguments)]
    pub(super) unsafe fn new_ar9287(
        device: BusDevice,
        cap: Cap<BusDeviceCap, Write>,
        bar: MmioRegion,
        report: super::calibration::ar9287::Report,
        grant: alloc::sync::Arc<super::admission::Grant>,
        image: &[u8],
        profile: super::mac::Profile,
        channel_mask: u16,
    ) -> Result<Self, Error> {
        let request = grant.request();
        if device.id.vendor != 0x168c
            || !matches!(device.id.device, 0x002d | 0x002e)
            || request.device != device.id.device
            || request.frequency_mhz != report.frequency_mhz
            || !(2412..=2472).contains(&report.frequency_mhz)
            || (report.frequency_mhz - 2412) % 5 != 0
            || image.len() != super::chips::MAP_9287.bytes()
            || image[18..20] != [profile.rx_chainmask, profile.tx_chainmask]
            || report.rx_chainmask != profile.rx_chainmask
            || profile.txbuf != 0x700
            || channel_mask & !0x1fff != 0
            || channel_mask & (1 << ((report.frequency_mhz - 2412) / 5)) == 0
        {
            return Err(Error::Packet);
        }
        let rf_silent = rf_silent(image)?;
        // The exact open-loop rate registers calibration programmed under
        // the signed ceiling are retained for every physical readback.
        let powers =
            super::phy::ar9287::power::plan(image, report.frequency_mhz, report.max_power_half_dbm)
                .map_err(|_| Error::Packet)?
                .registers;
        Ok(Self::assemble(
            device,
            cap,
            bar,
            Calibrated::Ar9287 {
                report,
                grant,
                profile,
                image: image.into(),
            },
            channel_mask,
            Some(InstalledPower::Twenty(powers)),
            rf_silent,
        ))
    }
    /// Discover, program and install one MSI vector while delivery stays
    /// disabled. Any failure leaves the owner on scheduled polling; a vector
    /// whose source cannot be proven disabled stays quarantined.
    pub(super) fn arm_msi(&self) -> bool {
        if self.msi.lock().is_some() || SIGNAL.lock().is_some() {
            return false;
        }
        let Ok(Ok(mut config)) =
            self.invoke_cfg(|| narf_bus::msi::enable_msi(&self.cap, &self.device, 1))
        else {
            return false;
        };
        let Ok(vector) = narf_interrupts::vector::alloc() else {
            return false;
        };
        // SAFETY: this sole retained function owns its cfg space; delivery
        // is disabled again below before any chip interrupt is unmasked.
        let programmed =
            self.invoke_cfg(|| unsafe { narf_bus::msi::program_msi(&mut config, 0, vector) });
        if !matches!(programmed, Ok(Ok(_))) {
            let _ = narf_interrupts::vector::free(vector);
            return false;
        }
        let signal = super::irq::Signal::new();
        *SIGNAL.lock() = Some(signal.clone());
        narf_interrupts::install_handler_named(vector, "ath9k", 0, vector_irq);
        let msi = Msi {
            config,
            vector,
            signal,
        };
        let disabled = self.invoke_cfg(|| {
            // SAFETY: same owned cfg space; MSI Enable stays clear until start.
            unsafe { narf_bus::msi::disable(&msi.config) }
        });
        if !matches!(disabled, Ok(Ok(()))) {
            quarantine(&msi);
            return false;
        }
        *self.msi.lock() = Some(msi);
        true
    }
    fn invoke_cfg<T>(&self, operation: impl FnOnce() -> T) -> Result<T, Error> {
        identity::invoke(&self.cap, operation).map_err(|_| Error::Access)
    }
}
fn quarantine(msi: &Msi) {
    narf_interrupts::disable_irq(msi.vector);
    narf_interrupts::dispatch::clear_all_wakers(msi.vector);
    narf_interrupts::synchronize_irq(msi.vector);
}
/// Disabled delivery: drain the handler and return the vector.
fn teardown(msi: Msi) {
    narf_interrupts::disable_irq(msi.vector);
    let _ = narf_interrupts::remove_handler(msi.vector, "ath9k", 0);
    narf_interrupts::dispatch::clear_all_wakers(msi.vector);
    narf_interrupts::synchronize_irq(msi.vector);
    let _ = narf_interrupts::vector::free(msi.vector);
    let mut signal = SIGNAL.lock();
    if signal
        .as_ref()
        .is_some_and(|s| alloc::sync::Arc::ptr_eq(s, &msi.signal))
    {
        *signal = None;
    }
}
impl Native {
    pub(super) fn qualify_ht(&mut self, facts: super::ht::Facts) {
        let grant = super::ht::Source::Registered.load(facts.clone()).ok();
        *self.ht.lock() = grant;
        self.ht_facts = Some(facts);
    }
    fn command(&self) -> Result<u16, Error> {
        let command =
            narf_bus::pci::read_command(&self.cap, &self.device).map_err(|_| Error::Access)?;
        if command == u16::MAX
            || command & (narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE)
                != narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE
        {
            return Err(Error::Access);
        }
        Ok(command)
    }
    fn extent(&self, reg: u64) -> Result<(), Error> {
        if reg & 3 != 0 || reg.checked_add(4).is_none_or(|end| end > self.bar.len) {
            Err(Error::Address)
        } else {
            Ok(())
        }
    }
    fn invoke<T>(&self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        identity::invoke(&self.cap, operation).map_err(|_| Error::Access)?
    }
    fn physical_readback(&self, active: bool, periodic: bool) -> Result<(), Error> {
        let command = self.command()?;
        if (command & narf_bus::pci::cmd::BUS_MASTER != 0) != active
            || self.active.load(Ordering::Acquire) != active
        {
            return Err(Error::Access);
        }
        let domain = narf_wireless::reg::db::snapshot().ok_or(Error::Access)?;
        if !self.calibrated.permitted(&domain) {
            return Err(Error::Access);
        }
        if let Some(powers) = &self.powers {
            // Raw loads stay inside this current BusDevice invocation;
            // using Port::read here would recursively enter access().
            let read = |register| -> Result<u32, Error> {
                self.extent(register)?;
                // SAFETY: full dword BAR bounds and current exclusive PCI
                // authority were checked above; no competing channel writer.
                Ok(unsafe { self.bar.read32(register) })
            };
            let geometry = self.geometry();
            if read(0x9874)? & 0x3fff_ffff
                != (0x3000_0000 | (u32::from(geometry.center()) * 0x10000 / 15))
                || read(0x9804)? & 0x7ff != geometry.turbo()
            {
                return Err(Error::Descriptor);
            }
            for (register, value) in powers.registers() {
                if read(*register)? != *value {
                    return Err(Error::Descriptor);
                }
            }
            if let InstalledPower::Forty(actual) = powers {
                let iq =
                    0x800 | (u32::from(actual.report.iq_i) << 5) | (actual.report.iq_q as u32 & 31);
                if read(0x8318)? != 1
                    || !periodic && (read(0x99b4)? != actual.adc || read(0x9920)? & 0xfff != iq)
                {
                    return Err(Error::Descriptor);
                }
            }
        }
        if let Some((gpio, polarity)) = self.rf_silent {
            self.extent(0x4048)?;
            // SAFETY: checked full input-register extent in current PCI
            // invocation, without recursively entering this access helper.
            let value = unsafe { self.bar.read32(0x4048) };
            if value == u32::MAX || (value & (1 << (12 + gpio)) != 0) == polarity {
                return Err(Error::Access);
            }
        }
        if periodic {
            let source = { self.ht.lock().clone().ok_or(Error::Access)? };
            source.periodic_physical(|register| {
                self.extent(register)?;
                // SAFETY: full checked extent in this current PCI invocation.
                Ok(unsafe { self.bar.read32(register) })
            })?;
            self.extent(0x7044)?;
            // SAFETY: invoked only inside the current retained PCI capability.
            if unsafe { self.bar.read32(0x7044) } & 15 != 2 {
                return Err(Error::State);
            }
        }
        Ok(())
    }
    fn invoke_packet_sources<T>(
        &self,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        let grant = { self.ht.lock().clone() };
        let ba = { self.ba.lock().clone() };
        let tx = { self.tx_ba.lock().clone() };
        let qos = { self.qos.lock().clone() };
        let operation = || match (ba, grant) {
            (Some(g), _) => g.invoke(operation),
            (None, Some(g)) => g.invoke(operation),
            (None, None) => operation(),
        };
        let operation = || {
            if let Some(g) = tx {
                g.invoke(operation)
            } else {
                operation()
            }
        };
        if let Some(g) = qos {
            g.invoke(operation)
        } else {
            operation()
        }
    }
}

#[cfg(feature = "kernel-test")]
fn smoke_ar9285_native_packet_revocation_precedes_config_dma_and_mmio(
) -> narf_kernel_test::TestResult {
    for id in [0x002b, 0x002c] {
        if let Err(error) = revoked_packet_authority(id) {
            return narf_kernel_test::TestResult::Fail(error);
        }
    }
    narf_kernel_test::TestResult::Pass
}
#[cfg(feature = "kernel-test")]
fn revoked_packet_authority(id: u16) -> Result<(), &'static str> {
    use narf_bus::{BarKind, BusAddr, BusKind, DeviceId, PcieAddr};
    let address = PcieAddr::new(0, 0, 7, 0);
    let device = BusDevice {
        addr: BusAddr::Pcie(address),
        id: DeviceId {
            vendor: 0x168c,
            device: id,
            class: 0x028000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::Pcie {
            addr: address,
            cfg_phys: narf_memory::PhysAddr::new(0),
        },
    };
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    let bar = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: super::phy::REQUIRED_BAR,
        kind: BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let report = super::calibration::Report {
        country: *b"US",
        frequency_mhz: 2412,
        max_power_half_dbm: 34,
        pa_offset: None,
        iq_i: 0,
        iq_q: 0,
        measured_noise_dbm: -115,
        noise_dbm: -115,
    };
    cap.revoke();
    // SAFETY: invalid config/BAR addresses are deliberately unreachable with
    // the revoked real object-table capability. No physical DMA is published.
    let Ok(native) =
        (unsafe { Native::new(device, cap, bar, report, &[0; super::EEPROM_4K_BYTES]) })
    else {
        return Err("native fixture shape");
    };
    let mut entered = false;
    if native.access(false, || {
        entered = true;
        Ok(())
    }) != Err(Error::Access)
        || entered
        || native.read(0x4020) != Err(Error::Access)
        || native.write(0xc, 0x1000) != Err(Error::Access)
        || native.allocate(128).is_ok()
        || native.master(true) != Err(Error::Access)
        || native.master(false) != Err(Error::Access)
    {
        return Err("revoked packet authority reached config, DMA or BAR");
    }
    if native.ht_grant().is_some() {
        return Err("legacy AR9285-silicon owner loaded HT without measured facts");
    }
    Ok(())
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!(
    "drivers/wireless/ath9k/packet",
    smoke_ar9285_native_packet_revocation_precedes_config_dma_and_mmio
);
impl Port for Native {
    fn periodic_grant(&self) -> Option<alloc::sync::Arc<super::periodic::Grant>> {
        self.periodic_source()
    }
    fn bind_periodic(
        &self,
        source: &alloc::sync::Arc<super::periodic::Grant>,
    ) -> Result<(), Error> {
        self.periodic_begin(source)
    }
    fn periodic_initial(
        &self,
    ) -> Result<
        (
            super::calibration::Report,
            Option<super::calibration::wide::WideReport>,
        ),
        Error,
    > {
        self.periodic_report()
    }
    fn periodic_read(&self, register: u64) -> Result<u32, Error> {
        self.periodic_read_raw(register)
    }
    fn periodic_write(&self, register: u64, value: u32) -> Result<(), Error> {
        self.periodic_write_raw(register, value)
    }
    fn periodic_install(&self, live: super::periodic::Live) -> Result<(), Error> {
        self.install_periodic(live)
    }
    fn periodic_failed(&self) {
        self.fail_periodic();
    }
    fn periodic_current(&self) -> Result<bool, Error> {
        match self.periodic_snapshot()? {
            Some(_) => self.access(self.active.load(Ordering::Acquire), || Ok(true)),
            None => Ok(false),
        }
    }
    fn ps_grant(&self) -> Option<alloc::sync::Arc<super::ps::Grant>> {
        if let Some(source) = self.ps.lock().clone() {
            return Some(source);
        }
        let source = super::ps::Source::Registered.load(self.ht_grant()?).ok()?;
        let mut retained = self.ps.lock();
        Some(retained.get_or_insert(source).clone())
    }
    fn station_ps_current(&self) -> Result<bool, Error> {
        if !self.ps_bound.load(Ordering::Acquire) {
            return Ok(false);
        }
        // Reuse actual current S/base/child/PCI and awake/physical checks.
        // access() does not call HT readback, so this cannot recurse through
        // the IER field whose admitted value this observation distinguishes.
        self.access(self.active.load(Ordering::Acquire), || Ok(true))
    }
    fn bind_ps(&self, source: &alloc::sync::Arc<super::ps::Grant>) -> Result<(), Error> {
        if self.has_periodic() {
            return Err(Error::State);
        }
        if self
            .ps_grant()
            .is_none_or(|current| !alloc::sync::Arc::ptr_eq(&current, source))
        {
            return Err(Error::Access);
        }
        source.check()?;
        self.access(self.active.load(Ordering::Acquire), || {
            self.command()?; // includes PCI INTx disabled for the polled path.
            self.ps_bound.store(true, Ordering::Release);
            Ok(())
        })
    }
    fn network_sleep(&self) -> Result<(), Error> {
        let source = self.ps.lock().clone().ok_or(Error::Access)?;
        if !self.ps_bound.load(Ordering::Acquire) || self.ps_failed.load(Ordering::Acquire) {
            return Err(Error::Access);
        }
        self.transmit_allowed()?;
        source.invoke(|| {
            self.invoke(|| {
                let raw = PowerRaw {
                    native: self,
                    source: &source,
                };
                // Mark an ambiguous attempt before any clock mutation. Ordinary
                // I/O can resume only after the full actual sleep proof succeeds.
                self.ps_failed.store(true, Ordering::Release);
                super::ps::hardware::network_sleep(&raw)?;
                self.ps_sleeping.store(true, Ordering::Release);
                self.ps_failed.store(false, Ordering::Release);
                Ok(())
            })
        })
    }
    fn channel_mask(&self) -> u16 {
        self.channel_mask
    }
    fn geometry(&self) -> super::channel_width::Geometry {
        match &self.powers {
            Some(InstalledPower::Forty(actual)) => actual.geometry,
            _ => super::channel_width::Geometry::from_frequency(self.calibrated.frequency_mhz())
                .expect("validated native primary"),
        }
    }
    fn frequency_mhz(&self) -> u16 {
        self.calibrated.frequency_mhz()
    }
    fn mac_clock(&self) -> super::mac::Clock {
        match &self.calibrated {
            Calibrated::Ar9285(_) => super::mac::Clock::Ofdm2g,
            Calibrated::Ar9287 { profile, .. } => profile.clock,
        }
    }
    fn tx_chainmask(&self) -> u8 {
        match &self.calibrated {
            Calibrated::Ar9285(_) => 1,
            Calibrated::Ar9287 { profile, .. } => profile.tx_chainmask,
        }
    }
    fn long_calibration(&self) -> Result<Option<i32>, Error> {
        let Calibrated::Ar9287 { report, image, .. } = &self.calibrated else {
            return Err(Error::State);
        };
        // Physical readback, current regulatory permission and the signed
        // record are re-proved by access() before the compensation runs.
        self.access(self.active.load(Ordering::Acquire), || {
            let mut io = LongCal {
                native: self,
                lost: false,
            };
            let delta = super::calibration::ar9287::olc_temp_compensation(
                &mut io,
                image,
                report.init_pdadc,
            );
            if io.lost {
                return Err(Error::Access);
            }
            delta.map_err(|_| Error::Descriptor)
        })
    }
    fn qos_grant(&self) -> Option<alloc::sync::Arc<super::qos::Grant>> {
        if let Some(g) = self.qos.lock().clone() {
            return Some(g);
        }
        let grant = super::qos::Source::Registered.load(self.ht_grant()?).ok()?;
        let mut retained = self.qos.lock();
        Some(retained.get_or_insert(grant).clone())
    }
    fn tx_ba_grant(&self) -> Option<alloc::sync::Arc<super::tx_ba::Grant>> {
        if let Some(g) = self.tx_ba.lock().clone() {
            return Some(g);
        }
        let grant = super::tx_ba::Source::Registered
            .load(self.ht_grant()?)
            .ok()?;
        let mut retained = self.tx_ba.lock();
        Some(retained.get_or_insert(grant).clone())
    }
    fn rx_ba_grant(&self) -> Option<alloc::sync::Arc<super::rx_ba::Grant>> {
        if let Some(grant) = self.ba.lock().clone() {
            return Some(grant);
        }
        let base = self.ht_grant()?;
        let grant = super::rx_ba::Source::Registered.load(base).ok()?;
        let mut retained = self.ba.lock();
        Some(retained.get_or_insert(grant).clone())
    }
    fn ht_grant(&self) -> Option<alloc::sync::Arc<super::ht::Grant>> {
        if let Some(grant) = self.ht.lock().clone() {
            return Some(grant);
        }
        // The report-bound request can be provisioned after legacy packet
        // preparation. Only an absent optional grant may be loaded; a revoked
        // established source is never replaced. The cache guard never spans lookup.
        let grant = super::ht::Source::Registered
            .load(self.ht_facts.clone()?)
            .ok()?;
        let mut retained = self.ht.lock();
        Some(retained.get_or_insert(grant).clone())
    }
    fn transmit_allowed(&self) -> Result<(), Error> {
        let domain = narf_wireless::reg::db::snapshot().ok_or(Error::Access)?;
        if !self.calibrated.permitted(&domain) {
            return Err(Error::Access);
        }
        // Includes physical per-channel synth/mode/power readbacks in the
        // same current PCI invocation as every original DMA/copy operation.
        if self.powers.is_some() {
            self.access(self.active.load(Ordering::Acquire), || Ok(()))?;
        }
        if let Some((gpio, polarity)) = self.rf_silent {
            if (self.read(0x4048)? & (1 << (12 + gpio)) != 0) == polarity {
                return Err(Error::Access);
            }
        }
        let grant = { self.ht.lock().clone() };
        if let Some(grant) = grant {
            grant.readback(self)?;
        }
        Ok(())
    }
    fn access<T>(
        &self,
        active: bool,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.invoke(|| {
            let ps = if self.ps_bound.load(Ordering::Acquire) {
                Some(self.ps.lock().clone().ok_or(Error::Access)?)
            } else {
                None
            };
            let action = || {
                if let Some(source) = ps.as_ref() {
                    if self.ps_failed.load(Ordering::Acquire) {
                        return Err(Error::Access);
                    }
                    let raw = PowerRaw {
                        native: self,
                        source,
                    };
                    if self.ps_sleeping.load(Ordering::Acquire) {
                        if let Err(error) = super::ps::hardware::awake(&raw) {
                            self.ps_failed.store(true, Ordering::Release);
                            return Err(error);
                        }
                        self.ps_sleeping.store(false, Ordering::Release);
                    } else if super::ps::hardware::Raw::read(&raw, 0x7044)? & 15 != 2 {
                        self.ps_failed.store(true, Ordering::Release);
                        return Err(Error::State);
                    }
                }
                let periodic = self.periodic_snapshot()?;
                if periodic.is_some() && ps.is_some() {
                    return Err(Error::State);
                }
                let action = || {
                    self.physical_readback(active, periodic.is_some())?;
                    if let Some((_, live)) = &periodic {
                        live.readback(&live_calibration::Raw { native: self })?;
                    }
                    self.invoke_packet_sources(operation)
                };
                match periodic.as_ref() {
                    Some((source, _)) => source.invoke_under(self.periodic_limit(), action),
                    None => action(),
                }
            };
            match ps.as_ref() {
                Some(source) => source.invoke(action),
                None => action(),
            }
        })
    }
    fn read(&self, reg: u64) -> Result<u32, Error> {
        self.access(self.active.load(Ordering::Acquire), || {
            self.extent(reg)?;
            // SAFETY: complete aligned BAR extent inside current invocation.
            let value = unsafe { self.bar.read32(reg) };
            if value == u32::MAX {
                self.extent(0x4020)?;
                // SAFETY: checked immutable silicon-ID dword in same BAR and invocation.
                if unsafe { self.bar.read32(0x4020) } == u32::MAX {
                    return Err(Error::Access);
                }
            }
            Ok(value)
        })
    }
    fn write(&self, reg: u64, value: u32) -> Result<(), Error> {
        self.access(self.active.load(Ordering::Acquire), || {
            self.extent(reg)?;
            // SAFETY: full aligned extent, exact exclusive retained PCI capability.
            unsafe {
                self.bar.write32(reg, value);
            }
            Ok(())
        })
    }
    fn allocate(&self, bytes: usize) -> Result<narf_io::DmaBuffer, Error> {
        let active = self.active.load(Ordering::Acquire);
        if active {
            // Only the distinct larger sender can extend retained TX storage
            // after BME/RX activation. Packet owns all-QCU-idle admission and
            // retains the old ring; no fresh mapping is reachable until its
            // separately checked descriptor publication.
            let source = self.tx_ba.lock().clone().ok_or(Error::Access)?;
            if source.members() <= 2 {
                return Err(Error::Access);
            }
            source.check()?;
        }
        self.access(active, || {
            if narf_io::iommu::mode() == narf_io::iommu::IommuMode::PerDomain {
                return Err(Error::Access);
            }
            narf_io::alloc_coherent_masked(
                bytes,
                narf_lib::id::DomainId::DRIVER_0,
                u64::from(u32::MAX),
            )
            .map_err(|_| Error::Memory)
        })
    }
    fn master(&self, enabled: bool) -> Result<(), Error> {
        self.invoke(|| {
            self.command()?;
            // Mark before the possibly ambiguous activation. Stopping remains
            // available independently, even after a failed BME readback.
            self.active.store(enabled, Ordering::Release);
            if enabled {
                narf_bus::pci::set_command(&self.cap, &self.device, narf_bus::pci::cmd::BUS_MASTER)
            } else {
                narf_bus::pci::clear_command(
                    &self.cap,
                    &self.device,
                    narf_bus::pci::cmd::BUS_MASTER,
                )
            }
            .map_err(|_| Error::Access)?;
            if (self.command()? & narf_bus::pci::cmd::BUS_MASTER != 0) != enabled {
                return Err(Error::Access);
            }
            Ok(())
        })
    }
    fn now_us(&self) -> u64 {
        narf_time::monotonic_ns() / 1000
    }
    fn ordered(&self) -> bool {
        // PCIe Device Control bit 4: Enable Relaxed Ordering.
        let Ok(read) = self.cap.derive::<narf_capabilities::Read>() else {
            return false;
        };
        matches!(
            self.invoke_cfg(|| narf_bus::pci_express::read_status(&read, &self.device)),
            Ok(Ok(status)) if status.device_control & (1 << 4) == 0
        )
    }
    fn interrupt(&self) -> Option<alloc::sync::Arc<super::irq::Signal>> {
        self.msi.lock().as_ref().map(|m| m.signal.clone())
    }
    fn deliver(&self, enabled: bool) -> Result<(), Error> {
        let mut retained = self.msi.lock();
        let Some(msi) = retained.as_ref() else {
            return Err(Error::State);
        };
        if enabled {
            narf_interrupts::enable_irq(msi.vector);
            // SAFETY: sole owner of this function's MSI capability.
            return match self.invoke_cfg(|| unsafe { narf_bus::msi::enable(&msi.config) }) {
                Ok(Ok(())) => Ok(()),
                _ => Err(Error::Access),
            };
        }
        // SAFETY: as above; a failed disable keeps the vector quarantined.
        let disabled = self.invoke_cfg(|| unsafe { narf_bus::msi::disable(&msi.config) });
        let msi = retained.take().ok_or(Error::State)?;
        drop(retained);
        if matches!(disabled, Ok(Ok(()))) {
            teardown(msi);
            Ok(())
        } else {
            quarantine(&msi);
            core::mem::forget(msi);
            Err(Error::Access)
        }
    }
}

/// Raw current-cap power operations; never recursively call Port::read.
struct PowerRaw<'a> {
    native: &'a Native,
    source: &'a super::ps::Grant,
}
impl super::ps::hardware::Raw for PowerRaw<'_> {
    fn read(&self, register: u64) -> Result<u32, Error> {
        self.source.invoke(|| {
            self.native.invoke(|| {
                let command = self.native.command()?;
                if (command & narf_bus::pci::cmd::BUS_MASTER != 0)
                    != self.native.active.load(Ordering::Acquire)
                {
                    return Err(Error::Access);
                }
                self.native.extent(register)?;
                // SAFETY: actual retained sole BAR, complete dword extent and
                // fresh source/PCI invocation; raw RTC access must precede AWAKE.
                let value = unsafe { self.native.bar.read32(register) };
                if value == u32::MAX {
                    Err(Error::Access)
                } else {
                    Ok(value)
                }
            })
        })
    }
    fn write(&self, register: u64, value: u32) -> Result<(), Error> {
        self.source.invoke(|| {
            self.native.invoke(|| {
                let command = self.native.command()?;
                if (command & narf_bus::pci::cmd::BUS_MASTER != 0)
                    != self.native.active.load(Ordering::Acquire)
                {
                    return Err(Error::Access);
                }
                self.native.extent(register)?;
                // SAFETY: same current sole PCI/source invocation and full BAR
                // extent, serialized by the retained packet/radio owner.
                unsafe {
                    self.native.bar.write32(register, value);
                }
                Ok(())
            })
        })
    }
    fn delay(&self, us: u64) {
        narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_us(us));
    }
    fn wait(&self, register: u64, mask: u32, expected: u32, budget_us: u64) -> Result<(), Error> {
        let mut failure = None;
        let done = narf_scheduler::responsive_spin_until(
            || match self.read(register) {
                Ok(value) => value & mask == expected,
                Err(error) => {
                    failure = Some(error);
                    true
                }
            },
            narf_time::Deadline::after_us(budget_us),
        );
        if let Some(error) = failure {
            Err(error)
        } else if done {
            Ok(())
        } else {
            Err(Error::Timeout)
        }
    }
}
