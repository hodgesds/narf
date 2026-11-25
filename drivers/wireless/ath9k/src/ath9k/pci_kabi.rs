//! The module build's PCI binding (`ath9k.ko`): every chip owner's built-in
//! `probe` bus half over the KABI instead of `narf_bus`, then that owner's
//! own `bring_up` — the same code the built-in probe runs.
//!
//! Linux `ath_pci_probe` order, as built in:
//!
//! 1. `narf_pci_identity`: vendor `0x168c` and a device one of the owners
//!    registers (AR9285/AR2427, AR5416/AR5418/AR9160, AR9280, AR9287, the
//!    AR9300 family).
//! 2. `narf_pci_prepare_probe` (D0, inherited decode/mastering parked), then
//!    the owners' own parking check (`qualcomm_pci::park`): Bus Master and
//!    Memory Space off, INTx Disable on, read back.
//! 3. BAR0 mapped while decode is parked; `narf_bar_len` reports its length
//!    (each owner's `bring_up` checks its `REQUIRED_BAR`); then Memory Space
//!    on and the policy read back (`map_bar_control`).
//! 4. Packet DMA is retained on teardown from the start: the driver proves
//!    its own DMA stop before every reset, but a module unload cannot.
//! 5. The 1 ms device poller (the executor's heartbeat), then the owner's
//!    `bring_up`: identity and EEPROM, board admission, INI/PLL/RF, the PCIe
//!    workarounds, and the calibration → packet → station → netdev task.
//!
//! One radio at a time, like the built-in singleton (`CLAIMED_ADDRESS`).
//! Bus mastering is never enabled here: the packet owner turns it on itself
//! (`Port::master`) only after its rings are in place, exactly as built in.

use core::fmt::Write as _;

use super::platform::compat::narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
use super::platform::compat::narf_bus::{
    BusAddr, BusDevice, DeviceId, MmioRegion, PcieAddr, ProbeError,
};
use super::platform::compat::narf_capabilities::Cap;
use super::platform::{self, Console};
use narf_module_rt::sync::SpinLock;

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
        pub fn narf_pci_identity(dev: u64, out: *mut u8, len: usize) -> i32;
        pub fn narf_bar_map(dev: u64, bar_idx: u8) -> u64;
        pub fn narf_bar_len(dev: u64, bar: u64, out_len: *mut u64) -> i32;
        pub fn narf_pci_command(dev: u64, clear: u16, set: u16, out_prev: *mut u16) -> i32;
        pub fn narf_spawn_poller(dev: u64, callback: usize, cookie: u64) -> i32;
        pub fn narf_dma_retain_on_teardown(dev: u64, retain: u32) -> i32;
    }
}

const ENODEV: i32 = -19;
const EBUSY: i32 = -16;
const EIO: i32 = -5;

/// The chip owner a PCI device id belongs to (the built-in registration
/// tables, `ath9k::register_ar9285` / `register_other_owners`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Owner {
    Ar9285,
    Ar5008,
    Ar9280,
    Ar9287,
    Ar9300,
}

/// Every (device, match name, owner) the module claims: the built-in
/// tables, unchanged.
fn ids() -> impl Iterator<Item = (u16, &'static str, Owner)> {
    let ar9285 = super::DEVICES
        .into_iter()
        .map(|(device, name, _)| (device, name, Owner::Ar9285));
    let tagged = |table: &'static [(u16, &'static str)], owner: Owner| {
        table
            .iter()
            .map(move |&(device, name)| (device, name, owner))
    };
    ar9285
        .chain(tagged(&super::ar5008_owner::DEVICES, Owner::Ar5008))
        .chain(tagged(&super::ar9280_owner::DEVICES, Owner::Ar9280))
        .chain(tagged(&super::ar9287_owner::DEVICES, Owner::Ar9287))
        .chain(tagged(&super::ar9300_owner::DEVICES, Owner::Ar9300))
}

fn owner_for(id: &DeviceId) -> Option<Owner> {
    if id.vendor != super::ATHEROS_PCI_VENDOR {
        return None;
    }
    ids()
        .find(|(device, _, _)| *device == id.device)
        .map(|(_, _, owner)| owner)
}

/// The bound function and its owner, for [`exit`].
static BOUND: SpinLock<Option<(Owner, BusDevice)>> = SpinLock::new(None);

/// How long [`exit`] drives the owner's removal before leaving its DMA
/// retained.
const REMOVE_BUDGET_MS: u64 = 5_000;

fn log(args: core::fmt::Arguments<'_>) {
    let _ = writeln!(Console, "  ath9k.ko: {}", args);
}

/// Register every owner's PCI ids; the kernel calls [`probe_c`] for a
/// match.
pub fn register() {
    for (device, name, _) in ids() {
        // SAFETY: `name` is 'static and `probe_c` is a valid extern "C" fn;
        // the loader unregisters the match before this image is unmapped.
        let rc = unsafe {
            ffi::narf_register_pci_driver(
                name.as_ptr(),
                name.len(),
                super::ATHEROS_PCI_VENDOR,
                device,
                probe_c as usize,
            )
        };
        if rc != 0 {
            log(format_args!(
                "PCI registration of {device:04x} failed ({rc})"
            ));
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
        addr: BusAddr::Pcie(PcieAddr {
            segment: u16_at(12),
            bus: record[14],
            device: devfn >> 3,
            function: devfn & 7,
        }),
        id: DeviceId {
            vendor: u16_at(0),
            device: u16_at(2),
            class: u32::from_le_bytes([record[9], record[10], record[11], 0]),
            subsystem_vendor: u16_at(4),
            subsystem_id: u16_at(6),
        },
    })
}

/// Change Command bits and return the register read back afterwards
/// (`qualcomm_pci`'s `Function` config access, then its `read`).
fn command(dev: u64, clear: u16, set: u16) -> Option<u16> {
    let mut readback = 0u16;
    // SAFETY: `readback` is a live local.
    let rc = unsafe { ffi::narf_pci_command(dev, clear, set, &mut readback) };
    (rc == 0).then_some(readback)
}

/// The bus half of the built-in `probe`: park, map BAR0, decode on.
fn bind(dev: u64) -> Result<MmioRegion, ProbeError> {
    const POLICY: u16 = BUS_MASTER | MEM_SPACE | INTX_DISABLE;
    // SAFETY: argument-only call on our fresh probe token.
    if unsafe { ffi::narf_pci_prepare_probe(dev) } != 0 {
        return Err(ProbeError::BadDevice);
    }
    // `qualcomm_pci::park(.., memory = false)`.
    if command(dev, BUS_MASTER | MEM_SPACE, INTX_DISABLE).is_none_or(|c| c & POLICY != INTX_DISABLE)
    {
        return Err(ProbeError::BadDevice);
    }
    // `map_bar_control`: map with decode parked, then memory on.
    // SAFETY: argument-only call on our probe token.
    let bar = unsafe { ffi::narf_bar_map(dev, 0) };
    let mut len = 0u64;
    // SAFETY: `len` is a live local.
    if bar == 0 || unsafe { ffi::narf_bar_len(dev, bar, &mut len) } != 0 {
        return Err(ProbeError::BadDevice);
    }
    if command(dev, 0, MEM_SPACE).is_none_or(|c| c & POLICY != MEM_SPACE | INTX_DISABLE) {
        return Err(ProbeError::BadDevice);
    }
    Ok(MmioRegion::new(bar, len))
}

/// Probe thunk the kernel's PCI match calls (task context, module domain).
extern "C" fn probe_c(dev: u64, _reserved: u64) -> i32 {
    // The singleton owns one radio (the built-in `CLAIMED_ADDRESS`); every
    // device export after this point takes the bound token.
    if platform::device() != 0 {
        return EBUSY;
    }
    let rc = probe_device(dev);
    if rc != 0 {
        platform::set_device(0);
    }
    rc
}

fn probe_device(dev: u64) -> i32 {
    platform::set_device(dev);
    let Some(device) = identity(dev) else {
        return ENODEV;
    };
    let Some(owner) = owner_for(&device.id) else {
        return ENODEV;
    };
    // The built-in reservation, before any hardware access. A failed
    // attempt keeps it: uncertain partial hardware state is never replayed
    // (remove releases it only after proving DMA stopped).
    {
        let mut claimed = super::CLAIMED_ADDRESS.lock();
        if claimed.is_some() {
            return EBUSY;
        }
        *claimed = Some(device.addr);
    }
    let mmio = match bind(dev) {
        Ok(mmio) => mmio,
        Err(error) => {
            log(format_args!(
                "{:04x}:{:04x} PCI binding failed: {:?}",
                device.id.vendor, device.id.device, error
            ));
            return EIO;
        }
    };
    // SAFETY: argument-only calls on our probe token; `poll` is a valid
    // extern "C" fn in this image, which the kernel retires before unmap.
    unsafe {
        let _ = ffi::narf_dma_retain_on_teardown(dev, 1);
        if ffi::narf_spawn_poller(dev, poll as usize, 0) != 0 {
            return EIO;
        }
    }
    let cap = Cap::new(dev);
    let result = match owner {
        Owner::Ar9285 => super::bring_up(device, cap, mmio),
        Owner::Ar5008 => super::ar5008_owner::bring_up(device, cap, mmio),
        Owner::Ar9280 => super::ar9280_owner::bring_up(device, cap, mmio),
        Owner::Ar9287 => super::ar9287_owner::bring_up(device, cap, mmio),
        Owner::Ar9300 => super::ar9300_owner::bring_up(device, cap, mmio),
    };
    match result {
        Ok(()) => {
            *BOUND.lock() = Some((owner, device));
            log(format_args!(
                "bound {:04x}:{:04x} ({:?} owner, subsys {:04x}:{:04x}), BAR0 {:#x} bytes",
                device.id.vendor,
                device.id.device,
                owner,
                device.id.subsystem_vendor,
                device.id.subsystem_id,
                mmio.len
            ));
            let _ = platform::EXEC.run();
            0
        }
        Err(error) => {
            log(format_args!("{owner:?} bring-up failed: {error:?}"));
            ENODEV
        }
    }
}

/// `narf_module_exit`: Linux `ath_pci_remove` for the bound function, the
/// built-in owner's own `remove`. The kernel has stopped the module's
/// callbacks, so the executor is driven here until that removal released
/// the reservation (its DMA-stop proof succeeded) or the budget ran out.
/// Only a proven stop lifts the teardown DMA retention; otherwise the
/// buffers stay quarantined after the image is gone.
pub fn exit() {
    let bound = BOUND.lock().take();
    if let Some((owner, device)) = bound {
        let dev = platform::device();
        let cap = Cap::new(dev);
        match owner {
            Owner::Ar9285 => super::remove(device, cap),
            Owner::Ar5008 => super::ar5008_owner::remove(device, cap),
            Owner::Ar9280 => super::ar9280_owner::remove(device, cap),
            Owner::Ar9287 => super::ar9287_owner::remove(device, cap),
            Owner::Ar9300 => super::ar9300_owner::remove(device, cap),
        }
        let deadline = narf_module_rt::time::Deadline::after_ms(REMOVE_BUDGET_MS);
        while super::CLAIMED_ADDRESS.lock().is_some() && !deadline.expired() {
            let _ = platform::EXEC.run();
            platform::delay_ns(1_000_000);
        }
        if super::CLAIMED_ADDRESS.lock().is_none() {
            // SAFETY: the owner's remove proved the device stopped mastering
            // and reclaimed every descriptor before releasing the address.
            let _ = unsafe { ffi::narf_dma_retain_on_teardown(dev, 0) };
            log(format_args!("{owner:?} removed; DMA reclaimed"));
        } else {
            log(format_args!(
                "{owner:?} removed; DMA stop unproven, buffers retained"
            ));
        }
    }
    platform::EXEC.stop();
    platform::set_device(0);
}
