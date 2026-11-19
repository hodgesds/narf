//! Loadable-module registration path for ath10k.
//!
//! Registration-only: the probe thunk returns `-ENOSYS` because the Wi-Fi
//! device datapath ABI is not yet exported. The built-in build registers the
//! full id table (`ath10k::ALL_PCI_MATCHES`) and drives the native transport;
//! this registers the same QCA ids as the module-build proof. See
//! `narf-drivers-net-tg3` for the registration-only shape.
//!
//! A module build links ONLY the `narf_register_pci_driver` KSYMTAB import —
//! no kernel crates — so the `.ko`'s undefined-symbol set stays within the
//! exported ABI (xtask's `nm -u` gate enforces it).

/// QCA PCI (vendor, device) matches, kept in sync with the built-in
/// `ath10k::hw::ALL_PCI_MATCHES`. Atheros vendor 0x168C + the Ubiquiti
/// QCA988X rebadge (0x0777).
const ALL_PCI_MATCHES: &[(u16, u16)] = &[
    (0x168c, 0x003c), // QCA988X
    (0x0777, 0x11ac), // QCA988X (Ubiquiti)
    (0x168c, 0x0050), // QCA9887
    (0x168c, 0x003e), // QCA6174
    (0x168c, 0x0041), // QCA6164
    (0x168c, 0x0040), // QCA99X0
    (0x168c, 0x0056), // QCA9888
    (0x168c, 0x0046), // QCA9984
    (0x168c, 0x0042), // QCA9377
    (0x168c, 0x0034), // AR9462
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
    const NAME: &[u8] = b"ath10k-module";
    for &(vendor, device) in ALL_PCI_MATCHES {
        // SAFETY: `NAME` is 'static; `probe_c` is a valid extern "C" fn. The
        // loader unregisters every match before unmapping this image.
        unsafe {
            narf_register_pci_driver(NAME.as_ptr(), NAME.len(), vendor, device, probe_c as usize);
        }
    }
}
