//! Loadable-module registration path for iwlwifi.
//!
//! Registration-only: the probe thunk returns `-ENOSYS` because the Wi-Fi
//! device datapath ABI is not yet exported. The built-in build registers the
//! full id table and drives the native transport; this registers the same
//! Intel ids as the module-build proof. See `narf-drivers-net-e1000` for the
//! datapath rationale and `narf-drivers-net-tg3` for the registration-only
//! shape.
//!
//! A module build links ONLY the `narf_register_pci_driver` KSYMTAB import —
//! no kernel crates — so the `.ko`'s undefined-symbol set stays within the
//! exported ABI (xtask's `nm -u` gate enforces it).

/// Intel.
const INTEL_VENDOR: u16 = 0x8086;

/// Device ids the built-in driver claims, kept in sync with the built-in
/// `iwlwifi::register` table.
const PCI_DIDS: &[u16] = &[
    0x2723, 0x02f0, 0x06f0, 0x34f0, 0x3df0, 0x4df0, 0x43f0, 0xa0f0, 0x7df0, 0x2725, 0x51f0, 0x51f1,
    0x7a70, 0x7af0, 0x7f70, 0x54f0, 0x2729, 0x7e40, 0x272b, 0x7740, 0x4d40, 0xa840, 0x6e70, 0x9327,
    0xd240, 0xd340, 0xe340, 0xe440,
];

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
    // -ENOSYS: the Wi-Fi device datapath ABI is not yet exported.
    -38
}

pub fn register() {
    const NAME: &[u8] = b"iwlwifi-module";
    for &device in PCI_DIDS {
        // SAFETY: `NAME` is 'static; `probe_c` is a valid extern "C" fn. The
        // loader unregisters every match before unmapping this image.
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
