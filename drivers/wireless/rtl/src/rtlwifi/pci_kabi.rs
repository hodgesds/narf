// SPDX-License-Identifier: GPL-2.0-or-later
//! The module build's PCI binding (`rtl.ko`, rtlwifi).
//!
//! The built-in `pci::probe` + `pci::bring_up`, step for step, over the KABI
//! instead of `narf-bus`; everything after the bus steps is the shared code
//! (`identity::identify`, `identity::admissible`, `pci::assemble`,
//! `pci::bind`):
//!
//! 1. `narf_pci_identity`: an rtlwifi id, and the PCI function (dual-MAC
//!    RTL8192DE parts pick their factory address and band by it).
//! 2. `narf_pci_prepare_probe`: inherited decode and mastering parked,
//!    INTx disabled, D0.
//! 3. BAR2 sized and mapped with Device attributes while decode is still
//!    off (`narf_bar_map_control`), then memory decode on — the built-in
//!    `pci_park::map_bar_control` order. Bus mastering stays off until the
//!    native station's packet owner enables it. `identity::control_bar_ok`
//!    on the length.
//! 4. ASPM off (`PciIo::disable_aspm`), as the built-in does for every
//!    rtlwifi id before touching the chip.
//! 5. `identity::identify` (power table, IRQ masks, EFUSE factory map) and
//!    `identity::admissible` (the chip's retained-profile facts).
//! 6. `pci::assemble` builds the firmware owner, preparation slot and native
//!    station device for an admitted function; `pci::bind` publishes it
//!    (`interface::publish` → `iface_module::attach`) and starts the same
//!    native preparation task the built-in starts.
//!
//! The kernel's 1 ms device poller drives the module's executor. DMA is
//! retained on teardown: removal's quiescence proof is not carried, so an
//! unload never frees memory the device may still own. One function binds.

use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, Ordering};

use alloc::boxed::Box;

use super::firmware_native::{Identity, PciIo};
use super::regs::{name_for, ALL_DEV_IDS, REALTEK_VENDOR};
use crate::platform::{self, Console, MmioRegion};

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
        pub fn narf_bar_map_control(dev: u64, bar_idx: u8) -> u64;
        pub fn narf_bar_len(dev: u64, bar: u64, out_len: *mut u64) -> i32;
        pub fn narf_spawn_poller(dev: u64, callback: usize, cookie: u64) -> i32;
        pub fn narf_dma_retain_on_teardown(dev: u64, retain: u32) -> i32;
    }
}

/// `PCI_COMMAND_MEMORY`.
const CMD_MEM_SPACE: u16 = 0x2;
/// rtlwifi's control BAR (`rtl_hal_cfg.bar_id`).
const CONTROL_BAR: u8 = 2;
const ENODEV: i32 = -19;
const EBUSY: i32 = -16;
const EIO: i32 = -5;
/// The name the PCI registry records for the module's matches.
const NAME: &[u8] = b"rtlwifi-module";

/// A function is bound (its token is the platform's device).
static BOUND: AtomicBool = AtomicBool::new(false);

/// Why the module's probe stopped.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ProbeError {
    PciAccess,
    RegisterBarMapFailed,
    Identify(super::identity::Error),
    Assemble(super::pci::ProbeError),
    Publish,
}

/// Register every rtlwifi PCI id; the kernel calls [`probe_c`] on a match.
pub fn register_pci_driver() {
    let mut registered = 0usize;
    for &device in crate::module_ids::PCI_DEVICES {
        // SAFETY: `NAME` is 'static; `probe_c` is a valid extern "C" fn; the
        // loader unregisters every match before unmapping this image.
        let rc = unsafe {
            ffi::narf_register_pci_driver(
                NAME.as_ptr(),
                NAME.len(),
                crate::module_ids::PCI_VENDOR,
                device,
                probe_c as usize,
            )
        };
        if rc == 0 {
            registered += 1;
        }
    }
    let _ = writeln!(
        Console,
        "  rtl.ko: {registered}/{} rtlwifi PCI ids registered",
        crate::module_ids::PCI_DEVICES.len()
    );
}

/// The device poller: the executor's heartbeat (every 1 ms).
extern "C" fn poll(_cookie: u64) -> i32 {
    platform::run_executor();
    0
}

/// Probe thunk the kernel's PCI match calls (task context, module domain).
extern "C" fn probe_c(dev: u64, _reserved: u64) -> i32 {
    // Every device export takes the bound token (`platform::device`): a
    // second function, PCI or USB, must not replace it.
    if platform::device() != 0 {
        return EBUSY;
    }
    if BOUND
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return EBUSY;
    }
    platform::set_device(dev);
    let rc = probe_device(dev);
    if rc != 0 {
        platform::set_device(0);
        BOUND.store(false, Ordering::Release);
    }
    rc
}

fn probe_device(dev: u64) -> i32 {
    let Some(identity) = Identity::read() else {
        return ENODEV;
    };
    let (vendor, did) = (identity.vendor, identity.device);
    if vendor != REALTEK_VENDOR || !ALL_DEV_IDS.contains(&did) {
        return ENODEV;
    }
    // Rings and firmware-owned memory are exposed from preparation on;
    // a teardown that cannot prove the device stopped must not free them.
    // SAFETY: argument-only call on our probe token.
    let _ = unsafe { ffi::narf_dma_retain_on_teardown(dev, 1) };
    match bring_up(dev, identity) {
        Ok((mac, native)) => {
            let _ = writeln!(
                Console,
                "  rtl.ko: probed {} ({vendor:04x}:{did:04x} subsys {:04x}:{:04x}) mac \
                 {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}: {} on {}",
                name_for(did),
                identity.subsystem_vendor,
                identity.subsystem_device,
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5],
                if native {
                    "native station, preparation started"
                } else {
                    "diagnostic profile (no admitted native station)"
                },
                crate::module_netdev::describe(),
            );
            // SAFETY: `poll` is a valid extern "C" fn in this image; the
            // kernel retires the poller before unmapping it.
            if unsafe { ffi::narf_spawn_poller(dev, poll as usize, 0) } != 0 {
                let _ = writeln!(
                    Console,
                    "  rtl.ko: no device poller; the station cannot run"
                );
                return EIO;
            }
            0
        }
        Err(error) => {
            let _ = writeln!(
                Console,
                "  rtl.ko: {} ({vendor:04x}:{did:04x}) bring-up failed: {error:?}",
                name_for(did),
            );
            match error {
                ProbeError::Publish => EIO,
                _ => ENODEV,
            }
        }
    }
}

/// Steps 2-6 of the module doc. A failure leaves teardown of the BAR and
/// any registration to the device context. Returns the factory MAC and
/// whether a native station was admitted.
fn bring_up(dev: u64, identity: Identity) -> Result<([u8; 6], bool), ProbeError> {
    let did = identity.device;
    // SAFETY: argument-only call on our probe token.
    if unsafe { ffi::narf_pci_prepare_probe(dev) } != 0 {
        return Err(ProbeError::PciAccess);
    }
    // SAFETY: argument-only call on our probe token.
    let bar = unsafe { ffi::narf_bar_map_control(dev, CONTROL_BAR) };
    if bar == 0 {
        return Err(ProbeError::RegisterBarMapFailed);
    }
    // SAFETY: argument-only call on our probe token.
    if unsafe { ffi::narf_pci_enable(dev, CMD_MEM_SPACE) } != 0 {
        return Err(ProbeError::PciAccess);
    }
    let mut len = 0u64;
    // SAFETY: `len` is a live local.
    if unsafe { ffi::narf_bar_len(dev, bar, &mut len) } != 0
        || !super::identity::control_bar_ok(did, len)
    {
        return Err(ProbeError::RegisterBarMapFailed);
    }
    let registers = MmioRegion::new(bar, len);
    let function = match identity.address {
        crate::platform::bus::BusAddr::Pcie(address) => address.function,
    };

    // SAFETY: the module's probe owns this function: BAR2 mapped above,
    // memory decoding on, bus mastering parked by `narf_pci_prepare_probe`.
    let control = unsafe { PciIo::new(identity, registers) };
    control.disable_aspm().map_err(|_| ProbeError::PciAccess)?;

    // SAFETY: as above, for the whole identification stage.
    let factory = Box::new(
        unsafe { super::identity::identify(&registers, did, function) }
            .map_err(ProbeError::Identify)?,
    );
    // SAFETY: as above.
    let admissible = unsafe { super::identity::admissible(&registers, did, function, &factory) };
    let mac = factory.mac;
    // SAFETY: probe parked this exact function and exclusively owns BAR2;
    // PciIo rechecks the command gate and identity at every access.
    let make_io = || unsafe { PciIo::new(identity, registers) };
    let device = super::pci::assemble(
        identity.address,
        did,
        registers,
        factory,
        admissible,
        make_io,
    )
    .map_err(ProbeError::Assemble)?;
    let native = device.native.is_some();
    if !super::pci::bind(device) {
        return Err(ProbeError::Publish);
    }
    Ok((mac, native))
}
