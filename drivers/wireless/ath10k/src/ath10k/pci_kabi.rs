//! The module build's PCI binding (`ath10k.ko`): registration and probe
//! over the KABI instead of `narf-bus`.
//!
//! The sequence is the built-in `probe` + `bring_up` step for step (Linux
//! `ath10k_pci_probe` up to `ath10k_pci_chip_reset`'s caller): identify the
//! function, refuse AR9462, park inherited decode/mastering
//! (`narf_pci_prepare_probe`), memory decode on, map BAR0 and check it
//! covers the family's register windows, wake the target and read the chip
//! id — then the same asynchronous `pci::boot_task` the built-in probe
//! spawns: reset, BMI, firmware/board/OTP download, HTC, WMI, HTT, the
//! radio and the station netdev. MSI, ASPM and bus mastering are the
//! transport's (`boot.rs`), over `platform::pci` / `platform::msi`.
//!
//! Every PCIe id the built-in driver binds is registered except AR9462
//! (168c:0034), which the built-in probe only refuses as ath9k's.

use core::fmt::Write as _;

use super::hw::{HwRev, ALL_PCI_MATCHES};
use super::platform::pci::{
    BusAddr, BusDevice, BusDeviceCap, Cap, DeviceId, MmioRegion, PcieAddr, Write,
};
use super::platform::{self, Console};

/// KABI exports the PCI binding calls.
mod ffi {
    unsafe extern "C" {
        pub fn narf_register_pci_driver(
            name: *const u8,
            len: usize,
            vendor: u16,
            device: u16,
            probe: usize,
        ) -> i32;
        pub fn narf_pci_prepare_probe(dev: u64) -> i32;
        pub fn narf_pci_enable(dev: u64, cmd_bits: u16) -> i32;
        pub fn narf_pci_identity(dev: u64, out: *mut u8, len: usize) -> i32;
        pub fn narf_bar_map(dev: u64, bar_idx: u8) -> u64;
        pub fn narf_bar_len(dev: u64, bar: u64, out_len: *mut u64) -> i32;
        pub fn narf_spawn_poller(dev: u64, callback: usize, cookie: u64) -> i32;
        pub fn narf_dma_retain_on_teardown(dev: u64, retain: u32) -> i32;
    }
}

const ENODEV: i32 = -19;
const EBUSY: i32 = -16;
const EIO: i32 = -5;

/// The PCI ids the module claims: every built-in match but AR9462.
pub fn module_matches() -> impl Iterator<Item = (u16, u16)> {
    ALL_PCI_MATCHES.iter().copied().filter(|&(vendor, device)| {
        !matches!(
            HwRev::from_pci_id(vendor, device),
            Some(HwRev::Ar9462Legacy) | None
        )
    })
}

/// Register the PCI ids; the kernel calls [`probe_c`] for a match.
pub fn register_pci_driver() {
    const NAME: &[u8] = b"ath10k";
    for (vendor, device) in module_matches() {
        // SAFETY: `NAME` is 'static and `probe_c` is a valid extern "C" fn;
        // the loader unregisters every match before this image is unmapped.
        let rc = unsafe {
            ffi::narf_register_pci_driver(
                NAME.as_ptr(),
                NAME.len(),
                vendor,
                device,
                probe_c as usize,
            )
        };
        if rc != 0 {
            let _ = writeln!(
                Console,
                "  ath10k.ko: PCI registration of {vendor:04x}:{device:04x} failed ({rc})"
            );
        }
    }
}

/// The device poller: the executor's heartbeat (every 1 ms).
extern "C" fn poll(_cookie: u64) -> i32 {
    let _ = platform::EXEC.run();
    0
}

/// The function's identity (`narf_pci_identity`).
fn identity(dev: u64) -> Option<BusDevice> {
    let mut record = [0u8; 16];
    // SAFETY: `record` names 16 writable bytes.
    if unsafe { ffi::narf_pci_identity(dev, record.as_mut_ptr(), record.len()) } != 0 {
        return None;
    }
    let u16_at = |i: usize| u16::from_le_bytes([record[i], record[i + 1]]);
    let devfn = record[15];
    Some(BusDevice {
        id: DeviceId {
            vendor: u16_at(0),
            device: u16_at(2),
            subsystem_vendor: u16_at(4),
            subsystem_id: u16_at(6),
        },
        addr: BusAddr::Pcie(PcieAddr {
            segment: u16_at(12),
            bus: record[14],
            device: devfn >> 3,
            function: devfn & 7,
        }),
    })
}

/// Probe thunk the kernel's PCI match calls (task context, module domain).
extern "C" fn probe_c(dev: u64, _reserved: u64) -> i32 {
    // Every device export after this point takes the bound token
    // (`platform::device`): a second function must not replace it.
    if super::pci::is_probed() {
        return EBUSY;
    }
    let rc = probe_device(dev);
    if rc != 0 && !super::pci::is_probed() {
        platform::set_device(0);
    }
    rc
}

fn probe_device(dev: u64) -> i32 {
    platform::set_device(dev);
    let Some(device) = identity(dev) else {
        return ENODEV;
    };
    let hw_rev = match HwRev::from_pci_id(device.id.vendor, device.id.device) {
        Some(HwRev::Ar9462Legacy) | None => return ENODEV,
        Some(rev) => rev,
    };
    // Rings, BMI bounce buffers and target host memory are published to the
    // firmware from power-up on; a teardown that cannot prove the device
    // stopped must not free them.
    // SAFETY: argument-only call on our probe token.
    let _ = unsafe { ffi::narf_dma_retain_on_teardown(dev, 1) };
    // SAFETY: argument-only calls on our probe token.
    let bar = unsafe {
        if ffi::narf_pci_prepare_probe(dev) != 0
            || ffi::narf_pci_enable(dev, platform::pci::cmd::MEM_SPACE) != 0
        {
            return EIO;
        }
        ffi::narf_bar_map(dev, 0)
    };
    let mut len = 0u64;
    // SAFETY: `len` is a live local.
    if bar == 0 || unsafe { ffi::narf_bar_len(dev, bar, &mut len) } != 0 {
        let _ = writeln!(Console, "  ath10k.ko: BAR0 map failed");
        return EIO;
    }
    let mmio: MmioRegion = MmioRegion::new(bar, len);
    // SAFETY: this probe owns the function's BARs; BAR0 was just mapped.
    let bound = match unsafe {
        super::pci::identify(
            mmio,
            device.addr,
            device.id.vendor,
            device.id.device,
            hw_rev,
        )
    } {
        Ok(bound) => bound,
        Err(error) => {
            let _ = writeln!(
                Console,
                "  ath10k.ko: bring_up failed for {} ({:04x}:{:04x}): {:?}",
                hw_rev.short_name(),
                device.id.vendor,
                device.id.device,
                error
            );
            return EIO;
        }
    };
    let _ = writeln!(
        Console,
        "  ath10k.ko: probed {} ({:04x}:{:04x} subsys {:04x}:{:04x}, chip_id={:#010x} rev={})",
        hw_rev.short_name(),
        device.id.vendor,
        device.id.device,
        device.id.subsystem_vendor,
        device.id.subsystem_id,
        bound.chip_id_raw,
        bound.chip_id_rev,
    );
    let _ = writeln!(
        Console,
        "  ath10k.ko:   firmware required at ath10k/{}/",
        hw_rev.short_name(),
    );
    let revision = bound.chip_id_rev;
    if !super::pci::bind_controller(bound) {
        return EBUSY;
    }
    // SAFETY: `poll` is a valid extern "C" fn in this image; the kernel
    // retires the poller before unmapping it.
    if unsafe { ffi::narf_spawn_poller(dev, poll as usize, 0) } != 0 {
        return EIO;
    }
    let cap: Cap<BusDeviceCap, Write> = Cap::probe_grant();
    platform::spawn(super::pci::boot_task(device, cap, mmio, hw_rev, revision));
    let _ = platform::EXEC.run();
    0
}
