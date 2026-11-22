//! Loadable-module registration path for ath9k (PCIe).
//!
//! Registration-only: the probe thunk returns `-ENOSYS` because the Wi-Fi
//! device datapath ABI is not yet exported. The built-in build registers the
//! Atheros PCIe id tables (`ath9k::DEVICES` and the per-chip owner `DEVICES`)
//! and drives the native transport; this registers the same ids as the
//! module-build proof, through the `narf_register_pci_driver` KSYMTAB export.
//!
//! A module build links ONLY that import — no kernel crates — so the `.ko`'s
//! undefined-symbol set stays within the exported ABI (xtask's `nm -u` gate
//! enforces it).

/// Qualcomm Atheros PCI vendor (`ath9k::ATHEROS_PCI_VENDOR`).
const ATHEROS_VENDOR: u16 = 0x168C;

/// The full Atheros PCIe id table across every ath9k chip owner: AR5416/9160
/// (ar5008), AR9280 (ar9280), AR9285/AR2427 (top-level), AR9287 (ar9287), and
/// the AR9300 family (ar9300).
const PCI_DIDS: &[u16] = &[
    0x0023, 0x0024, 0x0027, 0x0029, 0x002A, 0x002B, 0x002C, 0x002D, 0x002E, 0x0030, 0x0032, 0x0033,
    0x0034, 0x0036, 0x0037,
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
    const PCI_NAME: &[u8] = b"ath9k-module";
    for &device in PCI_DIDS {
        // SAFETY: `PCI_NAME` is 'static; `probe_c` is a valid extern "C" fn.
        // The loader unregisters every match before unmapping this image.
        unsafe {
            narf_register_pci_driver(
                PCI_NAME.as_ptr(),
                PCI_NAME.len(),
                ATHEROS_VENDOR,
                device,
                probe_c as usize,
            );
        }
    }
}
