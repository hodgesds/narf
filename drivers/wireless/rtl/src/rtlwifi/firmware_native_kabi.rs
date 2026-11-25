// SPDX-License-Identifier: GPL-2.0-or-later
//! The module build's retained rtlwifi PCI authority (`rtl.ko`): the
//! built-in `firmware_native::PciIo` API over the KABI.
//!
//! Built in, `PciIo` holds the function's `BusDevice` and live
//! `Cap<BusDeviceCap, Write>`, and every register access runs inside one
//! capability operation that first re-reads the PCI Command register and the
//! function's identity. Here the kernel holds the device authority in the
//! module's device context and re-validates it on every export, so the
//! module keeps the same per-access policy with what the KABI exposes:
//!
//! - **Command gate.** `narf_pci_command` (a read: clear = set = 0) before
//!   every access, through the
//!   built-in's `command_gate` (absent function, memory decode, INTx
//!   disabled, and bus mastering only in packet mode).
//! - **Identity.** `narf_pci_identity` must still report the probed vendor,
//!   device and subsystem ids. The BAR's physical address is the kernel's
//!   mapping and is not visible to a module.
//! - **Bus mastering** is set and cleared with `narf_pci_command`, which
//!   returns the register read back.
//! - **MSI.** One vector through `narf_msi_enable`; the vector's
//!   task-context upcall raises the signal and runs the executor. A module
//!   cannot free an MSI block, so a withdrawn vector stays granted (delivery
//!   off, no signal bound) and is reused by the next `arm_msi`.
//! - **ASPM.** The parent link's policy is not visible to a module, so the
//!   endpoint policy is "disabled", the built-in's answer for a bridge it
//!   does not know (`aspm_native::aspm_policy`).
//! - **System PM** (D-states, PME wake, config save/restore) is not carried.
use super::firmware_transport::{Error, Io};
use crate::platform::bus::{BusAddr, MmioRegion, PcieAddr};
use crate::platform::{self, IrqSafeSpinLock};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

/// KABI exports the PCI authority calls.
mod ffi {
    unsafe extern "C" {
        pub fn narf_pci_command(dev: u64, clear: u16, set: u16, out_cmd: *mut u16) -> i32;
        pub fn narf_pci_identity(dev: u64, out: *mut u8, len: usize) -> i32;
        pub fn narf_pcie_aspm(dev: u64, aspmc: u16, out_prev: *mut u16) -> i32;
        pub fn narf_msi_enable(
            dev: u64,
            want: u16,
            out_count: *mut u16,
            out_base_vector: *mut u16,
            out_addr: *mut u64,
            out_data: *mut u32,
        ) -> i32;
        pub fn narf_msi_set_enabled(dev: u64, enabled: u32) -> i32;
        pub fn narf_irq_set_handler(dev: u64, vector: u16, callback: usize, cookie: u64) -> i32;
    }
}

/// PCI command register bits (`narf_bus::pci::cmd`).
pub(super) mod cmd {
    pub const MEM_SPACE: u16 = 1 << 1;
    pub const BUS_MASTER: u16 = 1 << 2;
    pub const INTX_DISABLE: u16 = 1 << 10;
}
const EOPNOTSUPP: i32 = -95;

/// The probed function's identity (`narf_pci_identity`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Identity {
    pub(super) vendor: u16,
    pub(super) device: u16,
    pub(super) subsystem_vendor: u16,
    pub(super) subsystem_device: u16,
    pub(super) address: BusAddr,
}

impl Identity {
    /// Read the bound function's identity record.
    pub(super) fn read() -> Option<Self> {
        let mut record = [0u8; 16];
        // SAFETY: `record` names 16 writable bytes.
        if unsafe { ffi::narf_pci_identity(platform::device(), record.as_mut_ptr(), 16) } != 0 {
            return None;
        }
        let u16_at = |i: usize| u16::from_le_bytes([record[i], record[i + 1]]);
        let devfn = record[15];
        Some(Self {
            vendor: u16_at(0),
            device: u16_at(2),
            subsystem_vendor: u16_at(4),
            subsystem_device: u16_at(6),
            address: BusAddr::Pcie(PcieAddr::new(u16_at(12), record[14], devfn >> 3, devfn & 7)),
        })
    }
}

/// The granted MSI vector (kept across withdrawal: see the module doc).
static GRANTED: IrqSafeSpinLock<Option<u16>> = IrqSafeSpinLock::new(None);
/// The signal the vector raises while delivery is owned.
static SIGNAL: IrqSafeSpinLock<Option<Arc<super::irq::Signal>>> = IrqSafeSpinLock::new(None);

/// Task-context upcall for the vector: raise the retained signal (the
/// built-in top half's only effect), then run the woken work now.
extern "C" fn vector_upcall(_cookie: u64) -> i32 {
    let signal = SIGNAL.lock().clone();
    if let Some(signal) = signal {
        signal.raise();
    }
    platform::run_executor();
    0
}

pub struct PciIo {
    identity: Identity,
    registers: MmioRegion,
    packet_mode: AtomicBool,
    quarantined: AtomicBool,
    aspm_prepared: AtomicBool,
    msi: IrqSafeSpinLock<Option<Arc<super::irq::Signal>>>,
}

#[path = "rtl8723ae/park_kabi.rs"]
mod ae_park;

pub(super) fn command_gate(command: u16, packet_mode: bool) -> Result<(), Error> {
    if command == u16::MAX {
        return Err(Error::Gone);
    }
    if command & cmd::MEM_SPACE == 0
        || (!packet_mode && command & cmd::BUS_MASTER != 0)
        || command & cmd::INTX_DISABLE == 0
    {
        return Err(Error::Access);
    }
    Ok(())
}

/// The bound function's PCI Command register.
pub(super) fn command() -> Result<u16, Error> {
    read_command()
}

fn read_command() -> Result<u16, Error> {
    update_command(0, 0)
}

/// Clear, then set, Command bits; the register read back.
fn update_command(clear: u16, set: u16) -> Result<u16, Error> {
    let mut command = u16::MAX;
    // SAFETY: `command` is a live local.
    if unsafe { ffi::narf_pci_command(platform::device(), clear, set, &mut command) } != 0 {
        return Err(Error::Access);
    }
    Ok(command)
}

impl super::rtl8723ae::retained::Backend for PciIo {
    fn restrict_packets(&self) -> Result<(), Error> {
        self.restrict_ae_packets()
    }
    fn address(&self) -> BusAddr {
        self.identity.address
    }
    fn current<T>(&self, operation: impl FnOnce(&Self) -> Result<T, Error>) -> Result<T, Error> {
        self.access(0, 1, || {
            self.check_identity()?;
            operation(self)
        })?
    }
    fn identity(&self) -> Result<super::rtl8723ae::cold_storage::PciIdentity, Error> {
        <Self as super::rtl8723ae::retained::Backend>::current(self, |_| {
            if self.identity.vendor != 0x10ec || self.identity.device != 0x8723 {
                return Err(Error::Access);
            }
            Ok(super::rtl8723ae::cold_storage::PciIdentity::from_fields(
                [
                    self.identity.vendor,
                    self.identity.device,
                    self.identity.subsystem_vendor,
                    self.identity.subsystem_device,
                ],
                self.identity.address,
            ))
        })
    }
}

impl core::fmt::Debug for PciIo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RtlwifiPciFirmwareIo")
            .field("address", &self.identity.address)
            .finish_non_exhaustive()
    }
}

impl PciIo {
    pub(super) fn publication(&self) -> super::prepare::packet::Publication {
        super::prepare::packet::Publication::native()
    }
    /// The probed function's device id.
    pub(super) fn device_id(&self) -> u16 {
        self.identity.device
    }
    /// Caller owns the exact live BAR2 control region exclusively, as for
    /// the built-in constructor.
    pub(super) unsafe fn new(identity: Identity, registers: MmioRegion) -> Self {
        Self {
            identity,
            registers,
            packet_mode: AtomicBool::new(false),
            quarantined: AtomicBool::new(false),
            aspm_prepared: AtomicBool::new(false),
            msi: IrqSafeSpinLock::new(None),
        }
    }
    /// Linux `rtl_pci_intr_mode_msi`: one MSI vector, delivery left off.
    /// Any failure leaves the owner on scheduled polling.
    pub(super) fn arm_msi(&self) -> bool {
        if self.msi.lock().is_some() || self.quarantined.load(Ordering::Acquire) {
            return false;
        }
        let dev = platform::device();
        let vector = {
            let mut granted = GRANTED.lock();
            match *granted {
                Some(vector) => vector,
                None => {
                    let (mut count, mut base, mut addr, mut data) = (0u16, 0u16, 0u64, 0u32);
                    // SAFETY: the four outputs are live locals.
                    let rc = unsafe {
                        ffi::narf_msi_enable(dev, 1, &mut count, &mut base, &mut addr, &mut data)
                    };
                    if rc != 0 || count != 1 {
                        return false;
                    }
                    // SAFETY: `vector_upcall` is a valid extern "C" fn in this
                    // image, which the kernel unbinds before unmapping it.
                    if unsafe { ffi::narf_irq_set_handler(dev, base, vector_upcall as usize, 0) }
                        != 0
                    {
                        // The block stays the context's; delivery is off.
                        return false;
                    }
                    *granted = Some(base);
                    base
                }
            }
        };
        let _ = vector;
        let signal = super::irq::Signal::new();
        *SIGNAL.lock() = Some(signal.clone());
        *self.msi.lock() = Some(signal);
        true
    }
    pub(super) fn interrupt(&self) -> Option<Arc<super::irq::Signal>> {
        self.msi.lock().clone()
    }
    /// Enable delivery, or disable it and withdraw the signal. A failed
    /// disable quarantines the vector (no later re-arm).
    pub(super) fn deliver(&self, enabled: bool) -> bool {
        let mut retained = self.msi.lock();
        if retained.is_none() {
            return false;
        }
        let dev = platform::device();
        // SAFETY: argument-only calls on the bound token.
        if enabled && unsafe { ffi::narf_msi_set_enabled(dev, 1) } == 0 {
            return true;
        }
        // SAFETY: as above.
        let disabled = unsafe { ffi::narf_msi_set_enabled(dev, 0) } == 0;
        retained.take();
        *SIGNAL.lock() = None;
        if !disabled {
            self.quarantined.store(true, Ordering::Release);
        }
        false
    }
    /// Only the serialized replacement owner calls this after the old DMA
    /// retirement and IRQ withdrawal (the built-in contract).
    pub(super) fn parked_control(&self) -> Result<Self, Error> {
        if self.quarantined.load(Ordering::Acquire) || self.msi.lock().is_some() {
            return Err(Error::Gate);
        }
        self.check(0, 1)?;
        command_gate(read_command()?, false)?;
        self.check_identity()?;
        // SAFETY: the old IRQ and DMA owner is retired and current config
        // proves parked DMA, as built in.
        Ok(unsafe { Self::new(self.identity, self.registers) })
    }
    fn check_identity(&self) -> Result<(), Error> {
        let current = Identity::read().ok_or(Error::Gone)?;
        if current != self.identity {
            return Err(Error::Gone);
        }
        Ok(())
    }
    pub(super) fn function(&self) -> Option<u8> {
        match self.identity.address {
            BusAddr::Pcie(address) => Some(address.function),
        }
    }
    pub(super) fn read_efuse_physical(&self, addr: u16) -> Result<Option<u8>, Error> {
        self.access(0xcf, 1, || {
            self.check_identity()?;
            // SAFETY: exclusive control of the powered function; current
            // identity checked within this access. EFUSE read registers only.
            Ok(unsafe { super::efuse::read_physical_byte(&self.registers, addr) })
        })?
    }
    pub(super) fn verify_factory(&self, expected: &super::efuse::Factory) -> Result<(), Error> {
        self.access(0xcf, 1, || {
            self.check_identity()?;
            let function = self.function().ok_or(Error::Unsupported)?;
            // SAFETY: exclusive control after card enable; identity checked.
            let actual = unsafe {
                super::efuse::read_factory(&self.registers, self.identity.device, function)
            }
            .map_err(|_| Error::Gate)?;
            if actual.mac != expected.mac || actual.logical != expected.logical {
                return Err(Error::Gate);
            }
            Ok(())
        })?
    }
    pub(super) fn allocate_dma(&self, bytes: usize) -> Result<platform::io::DmaBuffer, Error> {
        self.check(0, 1)?;
        platform::io::alloc_coherent_masked(
            bytes,
            platform::lib::id::DomainId::DRIVER_0,
            u64::from(u32::MAX),
        )
        .map_err(|_| Error::NoMemory)
    }
    fn access<T>(&self, reg: u16, width: usize, operation: impl FnOnce() -> T) -> Result<T, Error> {
        self.check(reg, width)?;
        Ok(operation())
    }
    fn check(&self, reg: u16, width: usize) -> Result<(), Error> {
        command_gate(read_command()?, self.packet_mode.load(Ordering::Acquire))?;
        if u64::try_from(width)
            .ok()
            .and_then(|n| u64::from(reg).checked_add(n))
            .is_none_or(|end| end > self.registers.len)
        {
            return Err(Error::Access);
        }
        Ok(())
    }
    pub(super) fn packet_authority<T>(
        &self,
        active: bool,
        operation: impl FnOnce() -> Result<T, super::prepare::Error>,
    ) -> Result<Result<T, super::prepare::Error>, Error> {
        self.check(0, 1)?;
        let command = read_command()?;
        if (command & cmd::BUS_MASTER != 0) != active
            || (active && !self.packet_mode.load(Ordering::Acquire))
        {
            return Err(Error::Gate);
        }
        Ok(operation())
    }
    fn clear_bus_master() -> Result<(), Error> {
        let command = update_command(cmd::BUS_MASTER, 0)?;
        if command == u16::MAX {
            return Err(Error::Gone);
        }
        if command & cmd::BUS_MASTER != 0 {
            return Err(Error::Gate);
        }
        Ok(())
    }
    pub(super) fn packet_master(&self, enabled: bool) -> Result<(), Error> {
        self.check(0, 1)?;
        if enabled {
            self.packet_mode
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| Error::Gate)?;
        }
        let command = if enabled {
            update_command(0, cmd::BUS_MASTER)?
        } else {
            update_command(cmd::BUS_MASTER, 0)?
        };
        if (command & cmd::BUS_MASTER != 0) != enabled {
            return Err(Error::Gate);
        }
        Ok(())
    }
    pub(super) fn packet_kick(&self, queue_bit: u16) -> Result<(), Error> {
        // BK0/BE1/VI2/VO3 WMM rings, BEACON4 reserved page and MGNT6.
        if !matches!(queue_bit, 1 | 2 | 4 | 8 | 16 | 64) {
            return Err(Error::Gate);
        }
        self.packet_authority(true, || {
            self.check(0x300, 2)?;
            // SAFETY: aligned complete MMIO word inside the checked extent.
            unsafe { self.registers.write16(0x300, queue_bit) };
            // Flush the posted control write; not TX completion.
            // SAFETY: as above.
            let value = unsafe { self.registers.read16(0x300) };
            if value & 0xff00 != 0 {
                return Err(super::prepare::Error::Readback);
            }
            Ok(())
        })?
        .map_err(|_| Error::Gate)
    }
    /// `rtl8821ae` packet restriction (the built-in `park_native`): close
    /// the MAC through the scalar adapter, bus mastering off, delivery off.
    pub(in crate::rtlwifi) fn restrict_8821_packets(&self) -> Result<(), Error> {
        if self.identity.device != super::regs::RTL_DEV_8821AE {
            return Err(Error::Unsupported);
        }
        let io = ae_park::ParkIo(self);
        let result = super::rtl8821ae::park::close(&io, || {
            self.check_identity()?;
            Self::clear_bus_master()
        });
        let irq = self.check_identity().and_then(|()| {
            let _ = self.deliver(false);
            if self.msi.lock().is_some() || self.quarantined.load(Ordering::Acquire) {
                return Err(Error::Gate);
            }
            Ok(())
        });
        result.and(irq)
    }
    /// The built-in `restrict_ae_packets` (RTL8723AE terminal park).
    pub(in crate::rtlwifi) fn restrict_ae_packets(&self) -> Result<(), Error> {
        if self.identity.device != super::rtl8723ae::DEV_ID {
            return Err(Error::Unsupported);
        }
        let io = ae_park::ParkIo(self);
        let result = super::rtl8723ae::park::close(&io, || {
            self.check_identity()?;
            Self::clear_bus_master()
        });
        let irq = self.check_identity().and_then(|()| {
            let _ = self.deliver(false);
            if self.msi.lock().is_some() || self.quarantined.load(Ordering::Acquire) {
                return Err(Error::Gate);
            }
            Ok(())
        });
        let link = self.disable_aspm();
        result.and(irq).and(link)
    }
    /// Endpoint Link Control ASPM bits off (`narf_pcie_aspm`); a function
    /// without a PCI Express capability has none.
    pub(in crate::rtlwifi) fn disable_aspm(&self) -> Result<(), Error> {
        self.check(0, 1)?;
        self.check_identity()?;
        let mut previous = 0u16;
        // SAFETY: `previous` is a live local.
        match unsafe { ffi::narf_pcie_aspm(platform::device(), 0, &mut previous) } {
            0 | EOPNOTSUPP => Ok(()),
            _ => Err(Error::Access),
        }
    }
    /// The built-in reuses only a completed internal preparation here.
    pub(in crate::rtlwifi) async fn idle_aspm(&self, enabled: bool) -> Result<(), Error> {
        if !self.aspm_prepared.load(Ordering::Acquire) {
            return Ok(());
        }
        self.prepare_aspm(enabled).await
    }
    pub(in crate::rtlwifi) async fn prepare_aspm(&self, enabled: bool) -> Result<(), Error> {
        let profile = match self.identity.device {
            super::regs::RTL_DEV_8188EE => super::aspm::Profile::Rtl8188ee,
            super::regs::RTL_DEV_8723BE => super::aspm::Profile::Rtl8723be,
            super::regs::RTL_DEV_8192DE => super::aspm::Profile::Rtl8192de,
            _ => return Err(Error::Unsupported),
        };
        super::aspm::configure_for(self, profile, enabled).await
    }
}

impl super::aspm::Port for PciIo {}
impl super::aspm::PolicyPort for PciIo {
    /// The parent link's enabled policy is not visible to a module: the
    /// built-in answer for an unknown bridge, "disabled".
    fn desired(&self, _enabled: bool) -> Result<Option<u16>, Error> {
        self.check(0, 1)?;
        self.check_identity()?;
        Ok(Some(0))
    }
    fn control(&self, desired: u16) -> Result<(), Error> {
        if desired != 0 {
            return Err(Error::Unsupported);
        }
        self.disable_aspm()
    }
    fn prepared(&self) -> &AtomicBool {
        &self.aspm_prepared
    }
}

#[async_trait::async_trait]
impl Io for PciIo {
    fn restrict_8821_packets(&self) -> Result<(), Error> {
        PciIo::restrict_8821_packets(self)
    }
    fn read8(&self, reg: u16) -> Result<u8, Error> {
        // SAFETY: `access` checks authority, parked DMA and the byte extent.
        self.access(reg, 1, || unsafe { self.registers.read8(u64::from(reg)) })
    }
    fn read32(&self, reg: u16) -> Result<u32, Error> {
        if reg & 3 != 0 {
            return Err(Error::Access);
        }
        // SAFETY: aligned dword extent checked by `access`.
        self.access(reg, 4, || unsafe { self.registers.read32(u64::from(reg)) })
    }
    fn read16(&self, reg: u16) -> Result<u16, Error> {
        if reg & 1 != 0 {
            return Err(Error::Access);
        }
        // SAFETY: aligned word extent checked by `access`.
        self.access(reg, 2, || unsafe { self.registers.read16(u64::from(reg)) })
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), Error> {
        // SAFETY: as `read8`.
        self.access(reg, 1, || unsafe {
            self.registers.write8(u64::from(reg), value)
        })
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), Error> {
        if reg & 3 != 0 {
            return Err(Error::Access);
        }
        // SAFETY: as `read32`.
        self.access(reg, 4, || unsafe {
            self.registers.write32(u64::from(reg), value)
        })
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), Error> {
        if reg & 1 != 0 {
            return Err(Error::Access);
        }
        // SAFETY: as `read16`.
        self.access(reg, 2, || unsafe {
            self.registers.write16(u64::from(reg), value)
        })
    }
    fn write_bytes(&self, reg: u16, bytes: &[u8]) -> Result<(), Error> {
        self.access(reg, bytes.len(), || {
            for (i, byte) in bytes.iter().enumerate() {
                // SAFETY: the whole byte run was bounded by `access`.
                unsafe { self.registers.write8(u64::from(reg) + i as u64, *byte) };
            }
        })
    }
}
