//! PCIe ownership, bounded BAR0 window access, AI core discovery, and
//! interrupt parking. DMA remains disabled until an owned firmware/ring
//! lifecycle exists. Parking mailbox interrupts is not a chip reset.
//! Reference: Linux `brcmfmac/pcie.c` and `brcmfmac/chip.c`.

#![allow(dead_code)]

use narf_bus::{map_bar_control, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
use narf_lib::sync::IrqSafeSpinLock;

use super::chip::{self, Backplane, Chip};

// ── Hardware identification ────────────────────────────────────────
//
// The id table, `name_for` and `firmware_filename` live in `pcie_ids.rs`,
// shared with the module binding.
pub use super::pcie_ids::*;

// ── BAR0 register map ──────────────────────────────────────────────
//
// Per Linux `pcie.c` (lines ~119..150). The BAR0 window is 32 KiB and
// is split into two halves:
//   - The first 0x1000 holds the legacy "PCIE1" registers
//     (BAR0_WINDOW, BAR0_WRAPPERBASE, INTSTATUS, INTMASK, SBMBX,
//     LINK_STATUS_CTRL).
//   - The second 0x1000 holds the "PCIE2" register block — used by
//     newer parts for the mailbox / doorbell / configaddr/data dance.
//     `BRCMF_PCIE_BARO_PCIE_ENUM_OFFSET = 0x2000` is the start of the
//     PCIe2 block.
//
// The revision >=64 PCIe core uses different interrupt offsets. The
// discovery path selects those from the core revision, not firmware ABI.

/// BAR0 window size — `BRCMF_PCIE_REG_MAP_SIZE`. Linux `pcie.c` ~L119.
pub const BRCMF_PCIE_REG_MAP_SIZE: u64 = 32 * 1024;

/// BAR0 sliding-window register that selects the backplane address the
/// next BAR0 read targets. `BRCMF_PCIE_BAR0_WINDOW`. Linux `pcie.c`
/// ~L122.
pub const BRCMF_PCIE_BAR0_WINDOW: u64 = 0x80;

/// Offset of the "PCIE2 enum" register block inside BAR0.
/// `BRCMF_PCIE_BARO_PCIE_ENUM_OFFSET`. Linux `pcie.c` ~L127.
pub const BRCMF_PCIE_BARO_PCIE_ENUM_OFFSET: u64 = 0x2000;

/// PCIE2 register block: mailbox-mask register. Reads of this register
/// are the standard probe-time presence test — an all-FF return is the
/// "device gone" sentinel.
/// `BRCMF_PCIE_PCIE2REG_INTMASK`. Linux `pcie.c` ~L138.
pub const BRCMF_PCIE_PCIE2REG_INTMASK: u64 = 0x24;

/// PCIE2 register block: mailbox-int (RW1C status). Cleared as the
/// first step of the soft-reset prologue.
/// `BRCMF_PCIE_PCIE2REG_MAILBOXINT`. Linux `pcie.c` ~L139.
pub const BRCMF_PCIE_PCIE2REG_MAILBOXINT: u64 = 0x48;

/// PCIE2 register block: mailbox-mask. Linux writes 0 here to disable
/// all mailbox sources during release / probe.
/// `BRCMF_PCIE_PCIE2REG_MAILBOXMASK`. Linux `pcie.c` ~L140.
pub const BRCMF_PCIE_PCIE2REG_MAILBOXMASK: u64 = 0x4C;

/// PCIE2 register block: configuration-address. Used by the chip-id
/// discovery + BAR2 retarget flows in Linux `pcie.c` (~L720).
pub const BRCMF_PCIE_PCIE2REG_CONFIGADDR: u64 = 0x120;

/// PCIE2 register block: configuration-data. Companion to
/// `CONFIGADDR` — write the backplane offset to ADDR, read/write DATA.
pub const BRCMF_PCIE_PCIE2REG_CONFIGDATA: u64 = 0x124;

/// Sentinel a stale / absent BAR window returns on a 32-bit read.
const READ_GONE_U32: u32 = 0xFFFF_FFFF;

// ── Driver state ───────────────────────────────────────────────────

/// A parked PCIe device, retaining exclusive config-space authority.
/// No network interface is published by this ownership/discovery stage.
pub struct BrcmfmacDevice {
    pub(super) backplane: Option<PcieBackplane>,
    pub chip: Chip,
    pub device_id: u16,
}

/// The BAR0 sliding window is mutable device state. Keeping it and the
/// authority private prevents independent MMIO handles from racing a
/// select/access pair. Future async firmware work must own this value or
/// put it behind an async mutex, never await under CONTROLLER's IRQ lock.
pub(super) struct PcieBackplane {
    pub(super) proof: Option<alloc::sync::Arc<super::provision::Proof>>,
    pub(super) bar0: MmioRegion,
    pub(super) bar2: Option<MmioRegion>,
    pub(super) device: BusDevice,
    pub(super) cap: Cap<BusDeviceCap, Write>,
    pub(super) pcie_core: Option<chip::Core>,
    /// Retained MSI binding (`irq.rs`); `None` keeps polled service.
    pub(super) msi: Option<super::irq::Msi>,
}

/// Keep the actual device operation within the capability invocation rather
/// than returning a raw register handle after a separate validity check.
pub(super) fn invoke_registers<T>(
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

impl PcieBackplane {
    pub(super) fn qualified(&self) -> Result<(), chip::Error> {
        if let Some(proof) = &self.proof {
            proof.validate().map_err(|_| chip::Error::Access)?;
        }
        Ok(())
    }
    fn select(&mut self, address: u32) -> Result<u64, chip::Error> {
        if !chip::valid_address(address) {
            return Err(chip::Error::Address);
        }
        let window = address & !0xfff;
        // Retry the posted PCI configuration write once, as Linux's
        // brcmf_pcie_select_core does. This is a fixed transaction bound,
        // not a register wait loop. Every operation checks live authority.
        for _ in 0..2 {
            narf_bus::pci::write_config32(
                &self.cap,
                &self.device,
                BRCMF_PCIE_BAR0_WINDOW as u16,
                window,
            )
            .map_err(|_| chip::Error::Access)?;
            let selected = narf_bus::pci::read_config32(
                &self.cap,
                &self.device,
                BRCMF_PCIE_BAR0_WINDOW as u16,
            )
            .map_err(|_| chip::Error::Access)?;
            if selected == window {
                return Ok(u64::from(address & 0xfff));
            }
            if selected == u32::MAX {
                return Err(chip::Error::Gone);
            }
        }
        Err(chip::Error::Access)
    }
}

impl Backplane for PcieBackplane {
    fn read32(&mut self, address: u32) -> Result<u32, chip::Error> {
        self.qualified()?;
        let cap = self.cap;
        invoke_registers(&cap, || {
            let offset = self.select(address)?;
            // SAFETY: BAR0 has at least 4 KiB; select validates dword alignment
            // and offset <=4092. Exclusive window/access runs inside invoke.
            Ok(unsafe { self.bar0.read32(offset) })
        })
        .map_err(|_| chip::Error::Access)?
    }

    fn write32(&mut self, address: u32, value: u32) -> Result<(), chip::Error> {
        self.qualified()?;
        let cap = self.cap;
        invoke_registers(&cap, || {
            let offset = self.select(address)?;
            // SAFETY: same checked window and exclusive invocation as read32.
            unsafe { self.bar0.write32(offset, value) };
            Ok(())
        })
        .map_err(|_| chip::Error::Access)?
    }

    /// `brcmf_pcie_read_reg16` after `brcmf_pcie_buscore_prep_addr`.
    fn read16(&mut self, address: u32) -> Result<u16, chip::Error> {
        if address & 1 != 0 {
            return Err(chip::Error::Address);
        }
        self.qualified()?;
        let cap = self.cap;
        invoke_registers(&cap, || {
            let offset = self.select(address & !3)? + u64::from(address & 2);
            // SAFETY: the dword window was validated by select; the half
            // stays inside it. Exclusive window/access runs inside invoke.
            Ok(unsafe { self.bar0.read16(offset) })
        })
        .map_err(|_| chip::Error::Access)?
    }
}

impl core::fmt::Debug for BrcmfmacDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BrcmfmacDevice")
            .field("device_id", &format_args!("{:#06x}", self.device_id))
            .field("chip", &self.chip)
            .finish_non_exhaustive()
    }
}

/// Errors raised by the Stage-0 probe path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// `map_bar(device, 0)` failed.
    Bar0MapFailed,
    /// BAR0 window came back as all-FF on the PCIE2 mailbox-mask
    /// register — the device dropped off the link before we could
    /// drive it.
    DeviceGone,
    Bar0TooSmall,
    Bar2MapFailed,
    PciAccess,
    Discovery(chip::Error),
}

/// Single-instance live device. Multi-radio support comes with the
/// data-path follow-up.
static CONTROLLER: IrqSafeSpinLock<Option<BrcmfmacDevice>> = IrqSafeSpinLock::new(None);
static OWNED: IrqSafeSpinLock<Option<narf_bus::BusAddr>> = IrqSafeSpinLock::new(None);
/// A removed function whose DMA could not be proven stopped: its published
/// mappings stay pinned and the address is never brought up again.
static QUARANTINE: IrqSafeSpinLock<Option<narf_bus::BusAddr>> = IrqSafeSpinLock::new(None);

/// PCI driver match registration. Mirrors the Linux `brcmf_pcie_devices`
/// array (~L2724..L2754 in `pcie.c`).
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: BROADCOM_VENDOR,
                device: did,
            },
            probe,
        });
        narf_bus::register_pci_remove(name_for(did), remove);
    }
}

/// Linux v7.2 `pcie.c::brcmf_pcie_remove`: withdraw the published station
/// and stop the device behind the confirmed-stop proof before any ring or
/// buffer is released (`native_runtime::remove`). Only a proven (or never
/// started) owner releases the BDF claim; otherwise the function stays
/// quarantined with its mappings pinned.
fn remove(device: BusDevice, _cap: Cap<BusDeviceCap, Write>) {
    if *OWNED.lock() != Some(device.addr) {
        return;
    }
    *QUARANTINE.lock() = Some(device.addr);
    narf_scheduler::spawn(async move {
        let released = super::native_runtime::remove().await;
        // Discovery-only state; any retained bus went to the bootstrap.
        drop(CONTROLLER.lock().take());
        if released {
            release_bdf(&mut OWNED.lock(), device.addr);
            let mut quarantine = QUARANTINE.lock();
            if *quarantine == Some(device.addr) {
                *quarantine = None;
            }
        }
        narf_console::klog!(
            "brcmfmac: removed; DMA {}\n",
            if released {
                "reclaimed"
            } else {
                "pinned, address quarantined"
            }
        );
    });
}

/// BDF ownership decision for `probe`, kept pure for fixture coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Ownership {
    /// This probe claimed the BDF and must bring the device up.
    New,
    /// The BDF is already owned by an earlier successful probe.
    Existing,
    /// Another BDF owns the single-instance slot; park this device.
    Extra,
}

pub(super) fn claim_bdf(
    owner: &mut Option<narf_bus::BusAddr>,
    address: narf_bus::BusAddr,
) -> Ownership {
    match *owner {
        Some(owned) if owned == address => Ownership::Existing,
        Some(_) => Ownership::Extra,
        None => {
            *owner = Some(address);
            Ownership::New
        }
    }
}

/// Release a claim recorded by `claim_bdf` after a failed bring-up, so a
/// later probe can retry the device instead of finding it owned forever.
/// A mismatched address leaves the current owner's claim untouched.
pub(super) fn release_bdf(owner: &mut Option<narf_bus::BusAddr>, address: narf_bus::BusAddr) {
    if *owner == Some(address) {
        *owner = None;
    }
}

/// Probe entry — called by `narf-bus::driver_match` when a Broadcom
/// vendor/device pair we registered for surfaces.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if *QUARANTINE.lock() == Some(device.addr) {
        // Removal in progress or pinned DMA from a removed owner.
        return Err(narf_bus::ProbeError::BadDevice);
    }
    match claim_bdf(&mut OWNED.lock(), device.addr) {
        Ownership::Existing => return Ok(()),
        Ownership::Extra => {
            park_command(&device, &cap, false).map_err(|_| narf_bus::ProbeError::BadDevice)?;
            return Ok(());
        }
        Ownership::New => {}
    }

    // SAFETY: caller hands us exclusive BusDeviceCap authority for
    // this device's cfg + BARs.
    let mut dev = match unsafe { bring_up(device, cap) } {
        Ok(d) => d,
        Err(_) => {
            // Bring-up failed: drop the claim so the failure is not
            // reboot-only — a later probe may retry this device, and a
            // second Broadcom device is no longer parked behind it.
            release_bdf(&mut OWNED.lock(), device.addr);
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };

    super::native_runtime::start(&mut dev);
    let did = dev.device_id;
    *CONTROLLER.lock() = Some(dev);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(did)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    Ok(())
}

/// Claim a parked device: first revoke inherited bus mastering, then
/// map registers, discover actual cores, and mask the matching PCIe
/// interrupt registers. This does not start firmware or publish a NIC.
///
/// # Safety
/// Caller owns the device's BARs exclusively.
pub unsafe fn bring_up(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<BrcmfmacDevice, ProbeError> {
    // Verify decode and DMA parked before BAR sizing changes the BAR registers.
    park_command(&device, &cap, false)?;
    // SAFETY: exclusive BAR/config ownership, decoding and BME verified off.
    let bar0 = invoke_registers(&cap, || {
        // SAFETY: the invocation retains exclusive authority with decode and DMA off.
        unsafe { map_bar_control(&device, 0) }
    })
    .map_err(|_| ProbeError::PciAccess)?
    .map_err(|_| ProbeError::Bar0MapFailed)?;
    if bar0.len < 4096 {
        return Err(ProbeError::Bar0TooSmall);
    }
    // BCM43602 ids as before; other ids only where Linux binds them with a
    // vendor path the chip profiles implement (WCC/BCA, seeded or not).
    let bar2 = if matches!(
        device.id.device,
        BRCM_PCIE_43602_DEVICE_ID | BRCM_PCIE_43602_2G_DEVICE_ID | BRCM_PCIE_43602_5G_DEVICE_ID
    ) || super::chip_profile::pci_match(&device.id)
        .is_some_and(super::chip_profile::implemented)
    {
        // BAR2 is both dongle RAM and firmware control metadata; Device mapping
        // preserves the required index/descriptor publication ordering.
        // SAFETY: caller owns this function's BARs/config exclusively and
        // park_command verified bus mastering and memory decode disabled.
        Some(
            invoke_registers(&cap, || {
                // SAFETY: exclusive live authority; decode and DMA remain parked.
                unsafe { map_bar_control(&device, 2) }
            })
            .map_err(|_| ProbeError::PciAccess)?
            .map_err(|_| ProbeError::Bar2MapFailed)?,
        )
    } else {
        None
    };
    park_command(&device, &cap, true)?;
    let mut backplane = PcieBackplane {
        proof: None,
        bar0,
        bar2,
        device,
        cap,
        pcie_core: None,
        msi: None,
    };
    let chip = Chip::discover(&mut backplane).map_err(ProbeError::Discovery)?;
    backplane.pcie_core = chip.core(chip::CORE_PCIE2);
    chip.park_pcie(&mut backplane)
        .map_err(ProbeError::Discovery)?;
    Ok(BrcmfmacDevice {
        backplane: Some(backplane),
        chip,
        device_id: device.id.device,
    })
}

/// Test helper — `true` if the static slot has a bound device.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Borrow the bound controller.
pub fn with_controller<R>(f: impl FnOnce(&BrcmfmacDevice) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// Test-only reset of the bound slot.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
    *OWNED.lock() = None;
}

/// Shared production transition used before BAR sizing and before MMIO access.
fn configure_command(
    enable: bool,
    mut update: impl FnMut(u16, u16) -> Result<u16, ()>,
) -> Result<(), ProbeError> {
    use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
    let parked = update(BUS_MASTER | MEM_SPACE, INTX_DISABLE).map_err(|_| ProbeError::PciAccess)?;
    if parked & (BUS_MASTER | MEM_SPACE | INTX_DISABLE) != INTX_DISABLE {
        return Err(ProbeError::PciAccess);
    }
    if enable {
        let command = update(0, MEM_SPACE | INTX_DISABLE).map_err(|_| ProbeError::PciAccess)?;
        if command & (BUS_MASTER | MEM_SPACE | INTX_DISABLE) != MEM_SPACE | INTX_DISABLE {
            return Err(ProbeError::PciAccess);
        }
    }
    Ok(())
}
fn park_command(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
    enable: bool,
) -> Result<(), ProbeError> {
    invoke_registers(cap, || {
        configure_command(enable, |clear, set| {
            if clear != 0 {
                narf_bus::pci::clear_command(cap, device, clear).map_err(|_| ())?;
            }
            narf_bus::pci::set_command(cap, device, set).map_err(|_| ())?;
            narf_bus::pci::read_command(cap, device).map_err(|_| ())
        })
    })
    .map_err(|_| ProbeError::PciAccess)?
}

#[cfg(any(test, feature = "kernel-test"))]
mod command_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_brcmf_revoked_authority_blocks_native_register_operations() -> TestResult {
        use super::super::{boot::Bus as _, runtime::Bus as _};
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        let mut calls = 0;
        if invoke_registers(&cap, || calls += 1).is_err() || calls != 1 {
            return TestResult::Fail("live register invocation did not execute");
        }
        cap.revoke();
        if invoke_registers(&cap, || calls += 1) != Err(CapError::Revoked) || calls != 1 {
            return TestResult::Fail("revoked capability entered the register operation");
        }
        let address = narf_bus::PcieAddr::new(0, 0, 0, 0);
        let device = BusDevice {
            addr: narf_bus::BusAddr::Pcie(address),
            id: narf_bus::DeviceId {
                vendor: BROADCOM_VENDOR,
                device: BRCM_PCIE_43602_DEVICE_ID,
                class: 0x028000,
                subsystem_vendor: 0,
                subsystem_id: 0,
            },
            kind: narf_bus::BusKind::Pcie {
                addr: address,
                cfg_phys: narf_memory::PhysAddr::new(0),
            },
        };
        // Invalid mappings deliberately make an accidental post-revocation
        // hardware access a fault. No operation below may dereference them.
        let region = MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 4096,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let mut bus = PcieBackplane {
            proof: None,
            bar0: region,
            bar2: Some(region),
            device,
            cap,
            pcie_core: None,
            msi: None,
        };
        let mut out = [0xa5; 7];
        if bus.read32(chip::ENUM_BASE) != Err(chip::Error::Access)
            || bus.write32(chip::ENUM_BASE, 1) != Err(chip::Error::Access)
            || bus.read_tcm(1, &mut out) != Err(super::super::boot::Error::Access)
            || out != [0xa5; 7]
            || bus.write_tcm(1, &[1; 7]) != Err(super::super::boot::Error::Access)
            || bus.dma_enabled() != Err(super::super::boot::Error::Access)
            || bus.enable_dma() != Err(super::super::runtime::Error::Access)
            || bus.park_dma() != Err(super::super::runtime::Error::Access)
            || park_command(&device, &cap, false) != Err(ProbeError::PciAccess)
        {
            return TestResult::Fail("revoked authority admitted native BAR/config access");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/brcmfmac",
        smoke_brcmf_revoked_authority_blocks_native_register_operations
    );

    fn smoke_brcmf_native_parking_before_bar_sizing() -> TestResult {
        use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
        let mut value = BUS_MASTER | MEM_SPACE;
        let mut transcript = alloc::vec::Vec::new();
        if configure_command(true, |clear, set| {
            value = (value & !clear) | set;
            transcript.push((clear, set, value));
            Ok(value)
        })
        .is_err()
            || transcript
                != alloc::vec![
                    (BUS_MASTER | MEM_SPACE, INTX_DISABLE, INTX_DISABLE),
                    (0, MEM_SPACE | INTX_DISABLE, MEM_SPACE | INTX_DISABLE)
                ]
        {
            return TestResult::Fail("BAR sizing did not follow verified BME/decode-off phase");
        }
        for stale in [BUS_MASTER | INTX_DISABLE, MEM_SPACE | INTX_DISABLE, 0] {
            let mut calls = 0;
            if configure_command(true, |_, _| {
                calls += 1;
                Ok(stale)
            })
            .is_ok()
                || calls != 1
            {
                return TestResult::Fail("invalid parking readback reached decode enable");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/brcmfmac",
        smoke_brcmf_native_parking_before_bar_sizing
    );
}
