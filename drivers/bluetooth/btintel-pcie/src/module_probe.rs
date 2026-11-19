//! Loadable-module registration path for the Intel PCIe Bluetooth driver.
//!
//! Registration-only: the probe thunk returns `-ENOSYS` because the device
//! datapath ABI does not yet cover an HCI transport. The built-in build
//! registers the full id table and drives the controller; this registers the
//! same Intel ids as the module-build proof. See `narf-drivers-net-tg3` for
//! the registration-only shape.
//!
//! A module build links ONLY the `narf_register_pci_driver` KSYMTAB import —
//! no kernel crates — so the `.ko`'s undefined-symbol set stays within the
//! exported ABI (xtask's `nm -u` gate enforces it).

/// Intel.
const INTEL_VENDOR: u16 = 0x8086;

/// `btintel_pcie::SUPPORTED_DEVICE_IDS`: BlazarI (Wildcat Lake, Lunar Lake),
/// Scorpius (Panther Lake-H484/H404), Scorpius2 (Nova Lake-PCD-H/S).
const DIDS: &[u16] = &[0x4D76, 0xA876, 0xE376, 0xE476, 0xD346, 0x6E74];

const NAME: &[u8] = b"btintel_pcie-module";

unsafe extern "C" {
    fn narf_register_pci_driver(
        name: *const u8,
        name_len: usize,
        vendor: u16,
        device: u16,
        probe: usize,
    ) -> i32;
}

extern "C" fn probe_c(_dev_token: u64, _reserved: u64) -> i32 {
    // -ENOSYS: the HCI transport datapath ABI is not yet exported.
    -38
}

pub fn register() {
    for &device in DIDS {
        // SAFETY: `NAME` is 'static; `probe_c` is a valid extern "C" fn.
        // The loader unregisters every match before unmapping this image.
        unsafe {
            narf_register_pci_driver(
                NAME.as_ptr(),
                NAME.len(),
                INTEL_VENDOR,
                device,
                probe_c as usize,
            );
        }
    }
}
