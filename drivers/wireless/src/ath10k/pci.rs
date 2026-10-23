// SPDX-License-Identifier: GPL-2.0-or-later
//! PCI identification and retained asynchronous DMA-backed BMI bootstrap.
//! Probe disables inherited bus mastering, validates the per-chip BAR
//! windows and wakes the target. The boot task owns reset/CE7 target
//! configuration, CE0/CE1 BMI and calibrated firmware/BDF/OTP preparation.
//! Runtime HIF/HTC/WMI activation and interface registration remain open.

#![allow(dead_code)]

use core::fmt::Write as _;

use narf_bus::{map_bar_control, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;
use narf_time::Deadline;

use super::hw::*;

/// Retained PCI identity and the asynchronous boot transport's result.
pub struct Ath10kDevice {
    address: narf_bus::BusAddr,
    /// BAR0 MMIO window.
    pub mmio_bar0: MmioRegion,
    /// Decoded hardware family.
    pub hw_rev: HwRev,
    /// Raw 32-bit `SOC_CHIP_ID` register value.
    pub chip_id_raw: u32,
    /// Decoded chip-id-rev (the 4-bit field at bits [11:8]).
    pub chip_id_rev: u32,
    /// PCI device id we matched on.
    pub device_id: u16,
    /// PCI vendor id we matched on.
    pub vendor_id: u16,
    /// Published only after a real DMA-backed BMI target-info response.
    pub target_info: Option<super::bmi::TargetInfo>,
    /// Last boot failure; identification alone never implies a live WLAN.
    pub boot_error: Option<super::bmi::BmiError>,
    /// ROM-side calibrated image download; firmware is not yet activated.
    pub firmware_prepared: Option<FirmwarePrepared>,
    /// Firmware/profile/BDF/OTP failure after a successful BMI identity.
    pub firmware_error: Option<super::firmware::Error>,
}

#[derive(Clone, Copy, Debug)]
pub struct FirmwarePrepared {
    pub directory: &'static str,
    pub api: u8,
    pub wmi_operations: u32,
    pub htt_operations: u32,
}

impl core::fmt::Debug for Ath10kDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ath10kDevice")
            .field("hw_rev", &self.hw_rev)
            .field("chip_id_raw", &format_args!("{:#010x}", self.chip_id_raw))
            .field("chip_id_rev", &self.chip_id_rev)
            .field("vendor_id", &format_args!("{:#06x}", self.vendor_id))
            .field("device_id", &format_args!("{:#06x}", self.device_id))
            .finish_non_exhaustive()
    }
}

/// Errors raised by the Stage 0 bring-up path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// `map_bar(device, 0)` failed. Most likely the BAR isn't
    /// implemented at all (wrong device) or the cap-list claim raced
    /// another driver.
    Bar0MapFailed,
    /// `SOC_CHIP_ID` read returned the all-FF "device gone" sentinel
    /// — the part isn't really there.
    DeviceGone,
    /// Global-reset never released within the deadline.
    ResetTimeout,
    /// The PCI ID matches AR9462, which is ath9k's territory; ath10k
    /// shouldn't bind it. Surfaced explicitly rather than silently
    /// succeeding so the probe trace shows what happened.
    LegacyChipRejected,
    /// The mapped BAR cannot cover this family's register windows.
    BadBar,
    /// The target's PCI-local RTC did not reach its awake state.
    WakeTimeout,
}

/// All-FF sentinel for a 32-bit MMIO read on absent silicon.
const READ_GONE_U32: u32 = 0xFFFF_FFFF;

/// Single-instance live device. Same shape as `rtw88` — laptops only
/// ship one ath10k radio, so single-instance is fine for now.
static CONTROLLER: IrqSafeSpinLock<Option<Ath10kDevice>> = IrqSafeSpinLock::new(None);

// The boot session retains its PCI authority, awake target and all DMA
// allocations. Future firmware/runtime work takes this async mutex, never
// an IRQ-disabling controller guard, while awaiting CE completions.
struct BootSession {
    bmi: super::bmi::Bmi<super::boot::PciBoot>,
    image: super::firmware::Image,
    profile: super::profile::Profile,
}
static SESSION: narf_lib::mutex::Mutex<Option<BootSession>> = narf_lib::mutex::Mutex::new(None);

/// PCI driver match registration. One entry per supported device id,
/// each with a unique `name` so the bus registry doesn't collapse them.
pub fn register_pci_driver() {
    for &(vendor, device) in ALL_PCI_MATCHES {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(vendor, device),
            kind: narf_bus::MatchKind::VendorDevice { vendor, device },
            probe,
        });
    }
}

/// Human-readable driver name keyed on the matched `(vendor, device)`.
/// Used as `PciMatch.name` + `BoundDriver.name`. Must be a `'static`
/// string — the bus registry stores it by reference.
pub const fn name_for(vendor: u16, device: u16) -> &'static str {
    match (vendor, device) {
        (ATHEROS_VENDOR, QCA988X_DEVICE_ID) => "ath10k-qca988x",
        (UBNT_VENDOR, QCA988X_UBNT_DEVICE_ID) => "ath10k-qca988x-ubnt",
        (ATHEROS_VENDOR, QCA6174_DEVICE_ID) => "ath10k-qca6174",
        (ATHEROS_VENDOR, QCA6164_DEVICE_ID) => "ath10k-qca6164",
        (ATHEROS_VENDOR, QCA99X0_DEVICE_ID) => "ath10k-qca99x0",
        (ATHEROS_VENDOR, QCA9888_DEVICE_ID) => "ath10k-qca9888",
        (ATHEROS_VENDOR, QCA9984_DEVICE_ID) => "ath10k-qca9984",
        (ATHEROS_VENDOR, QCA9377_DEVICE_ID) => "ath10k-qca9377",
        (ATHEROS_VENDOR, AR9462_DEVICE_ID) => "ath10k-ar9462-reject",
        _ => "ath10k",
    }
}

/// Probe entry called by `narf-bus::driver_match` when a matching
/// `(vendor, device)` pair surfaces.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    // Resolve hw_rev from the PCI ID first so we can refuse AR9462
    // before doing any MMIO.
    let hw_rev = match HwRev::from_pci_id(device.id.vendor, device.id.device) {
        Some(HwRev::Ar9462Legacy) => {
            let _ = writeln!(
                narf_console::Writer,
                "  ath10k: AR9462 (168c:0034) is ath9k territory, skipping"
            );
            return Err(narf_bus::ProbeError::NotForThisDriver);
        }
        Some(r) => r,
        None => return Err(narf_bus::ProbeError::NotForThisDriver),
    };

    // Verify inherited DMA is parked before any MMIO. An additional
    // matched radio is parked with memory decode off, never reported bound.
    let owner = CONTROLLER
        .lock()
        .as_ref()
        .map(|controller| controller.address);
    let occupied = owner.is_some();
    crate::qualcomm_pci::park(&device, &cap, !occupied, owner)?;
    if occupied {
        return Err(narf_bus::ProbeError::Other(
            "ath10k singleton already owns another radio",
        ));
    }

    // SAFETY: bus dispatch hands us exclusive BusDeviceCap authority
    // for this device's cfg + BARs for the lifetime of this call.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let result = unsafe { bring_up(&device, hw_rev) };
    let dev = match result {
        Ok(d) => d,
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  ath10k: bring_up failed for {} ({:04x}:{:04x}): {:?}",
                hw_rev.short_name(),
                device.id.vendor,
                device.id.device,
                e,
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };

    // Log the bind. Mirrors iwlwifi's preamble — single-line summary
    // so dmesg stays readable.
    let _ = writeln!(
        narf_console::Writer,
        "  ath10k: probed {} ({:04x}:{:04x}, chip_id={:#010x} rev={})",
        hw_rev.short_name(),
        dev.vendor_id,
        dev.device_id,
        dev.chip_id_raw,
        dev.chip_id_rev,
    );
    // Exact profile selection needs the asynchronous BMI target version.
    let _ = writeln!(
        narf_console::Writer,
        "  ath10k:   firmware required at /firmware/ath10k/{}/",
        hw_rev.short_name(),
    );

    let mmio = dev.mmio_bar0;
    let revision = dev.chip_id_rev;
    let vid = dev.vendor_id;
    let did = dev.device_id;
    *CONTROLLER.lock() = Some(dev);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(vid, did)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(vid),
        pci_did: Some(did),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    narf_scheduler::spawn(boot_task(device, cap, mmio, hw_rev, revision));

    Ok(())
}

/// Map and wake the device and read the fuse-backed chip identity.
/// No reset or DMA starts until the asynchronous boot owner takes over.
///
/// # Safety
/// Caller owns the device's BARs exclusively.
pub unsafe fn bring_up(device: &BusDevice, hw_rev: HwRev) -> Result<Ath10kDevice, ProbeError> {
    // SAFETY: caller-asserted BAR exclusivity.
    let mmio_bar0 = unsafe { map_bar_control(device, 0) }.map_err(|_| ProbeError::Bar0MapFailed)?;

    let registers = hw_rev.registers().ok_or(ProbeError::LegacyChipRejected)?;
    let required = (registers.pcie_local + 12)
        .max(registers.chip_id + 4)
        .max(registers.soc_core + 24)
        .max(registers.ce_base(7).unwrap() + 0x54);
    if mmio_bar0.len < required {
        return Err(ProbeError::BadBar);
    }
    // Force the target awake before accessing the RTC/CE windows. The
    // register offsets are relative to the per-chip PCI-local window.
    // SAFETY: probe owns the BAR and the bounds above cover this wake register.
    unsafe {
        mmio_bar0.write32(registers.pcie_local + PCIE_SOC_WAKE_ADDRESS, 1);
    }
    let on = if hw_rev == HwRev::Qca99x0 { 7 } else { 3 };
    let mut gone = false;
    let awake = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: the BAR bounds above cover PCI-local RTC state.
            let state = unsafe { mmio_bar0.read32(registers.pcie_local + RTC_STATE_ADDRESS) };
            if state == u32::MAX {
                gone = true;
                return true;
            }
            state & RTC_STATE_V_MASK == on
        },
        Deadline::after_ms(30),
    );
    if gone {
        return Err(ProbeError::DeviceGone);
    }
    if !awake {
        return Err(ProbeError::WakeTimeout);
    }

    // Presence test — the first read of any BAR0
    // register returns all-FF if the device dropped off the link.
    // `SOC_CHIP_ID` is always present; pick it.
    let chip_id_off = soc_chip_id_address(hw_rev);
    // SAFETY: the selected full BAR-relative offset was checked above.
    let pre_reset_chip_id = unsafe { mmio_bar0.read32(chip_id_off) };
    if pre_reset_chip_id == READ_GONE_U32 {
        return Err(ProbeError::DeviceGone);
    }

    // Re-read the fuse-backed value for the operator-visible log.
    // SAFETY: same.
    let chip_id_raw = unsafe { mmio_bar0.read32(chip_id_off) };
    if chip_id_raw == READ_GONE_U32 {
        return Err(ProbeError::DeviceGone);
    }
    let rev = chip_id_rev(chip_id_raw);

    Ok(Ath10kDevice {
        address: device.addr,
        mmio_bar0,
        hw_rev,
        chip_id_raw,
        chip_id_rev: rev,
        vendor_id: device.id.vendor,
        device_id: device.id.device,
        target_info: None,
        boot_error: None,
        firmware_prepared: None,
        firmware_error: None,
    })
}

async fn boot_task(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    mmio: MmioRegion,
    hw: HwRev,
    revision: u32,
) {
    let result = async {
        let mut transport = super::boot::PciBoot::new(device, cap, mmio, hw)?;
        transport.power_up(revision).await?;
        let mut bmi = super::bmi::Bmi::new(transport);
        let info = bmi.target_info().await?;
        Ok::<_, super::bmi::BmiError>((bmi, info))
    }
    .await;
    match result {
        Ok((mut bmi, info)) => {
            if let Some(controller) = CONTROLLER.lock().as_mut() {
                controller.target_info = Some(info);
            }
            let prepared = async {
                let profile = super::profile::Profile::select(device.id.device, info.version)
                    .ok_or(super::firmware::Error::Unsupported)?;
                let mut files = super::firmware::RegistryFiles::new()?;
                let deadline = Deadline::after_ms(60_000);
                let image = loop {
                    match super::firmware::Image::load(&mut files, profile) {
                        Ok(image) => break image,
                        Err(super::firmware::Error::Missing) if !deadline.expired() => {
                            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000))
                                .await;
                        }
                        Err(error) => return Err(error),
                    }
                };
                let identity = super::firmware::Identity {
                    vendor: device.id.vendor,
                    device: device.id.device,
                    subsystem_vendor: device.id.subsystem_vendor,
                    subsystem_device: device.id.subsystem_id,
                };
                let variant = crate::ath11k::board::check_smbios().bdf_ext;
                let variant = core::str::from_utf8(&variant)
                    .map_err(|_| super::firmware::Error::Unsupported)?;
                super::firmware::prepare(&mut bmi, &mut files, profile, identity, variant, &image)
                    .await?;
                let status = FirmwarePrepared {
                    directory: profile.directory,
                    api: image.api,
                    wmi_operations: image.wmi,
                    htt_operations: image.htt,
                };
                *SESSION.lock().await = Some(BootSession {
                    bmi,
                    image,
                    profile,
                });
                Ok::<_, super::firmware::Error>(status)
            }
            .await;
            match prepared {
                Ok(status) => {
                    if let Some(controller) = CONTROLLER.lock().as_mut() {
                        controller.firmware_prepared = Some(status);
                    }
                    let _ = writeln!(narf_console::Writer,
                        "  ath10k: {} api {} WMI {} HTT {} calibrated image downloaded; HIF activation pending",
                        status.directory, status.api, status.wmi_operations, status.htt_operations);
                }
                Err(error) => {
                    if let Some(controller) = CONTROLLER.lock().as_mut() {
                        controller.firmware_error = Some(error.clone());
                    }
                    let _ = writeln!(
                        narf_console::Writer,
                        "  ath10k: firmware/BDF/OTP preparation failed: {:?}",
                        error
                    );
                }
            }
        }
        Err(error) => {
            if let Some(controller) = CONTROLLER.lock().as_mut() {
                controller.boot_error = Some(error);
            }
            let _ = writeln!(
                narf_console::Writer,
                "  ath10k: BMI bootstrap failed: {:?}",
                error
            );
        }
    }
}

/// Test helper — `true` if the static slot has a bound device.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Borrow the bound controller. Returns `None` if probe hasn't run.
pub fn with_controller<R>(f: impl FnOnce(&Ath10kDevice) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// Test-only reset of the bound slot.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}
