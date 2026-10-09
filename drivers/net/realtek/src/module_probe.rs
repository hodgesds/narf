//! Loadable-module registration path for the Realtek family.
//!
//! Registration-only: the probe thunk returns `-ENOSYS` because the device
//! datapath ABI is not yet exported. The built-in build registers every
//! family member's full id table; this registers one representative id per
//! sub-driver as the module-build proof.

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
    -38
}

/// `(vendor, device, name)` representatives: r8169 (RTL8168), RTL8125,
/// RTL8126, RTL8127.
const IDS: &[(u16, u16, &[u8])] = &[
    (0x10EC, 0x8168, b"r8169-8168"),
    (0x10EC, 0x8125, b"rtl8125"),
    (0x10EC, 0x8126, b"rtl8126"),
    (0x10EC, 0x8127, b"rtl8127"),
];

pub fn register() {
    for &(vendor, device, name) in IDS {
        // SAFETY: each `name` is a 'static byte string; `probe_c` is a valid
        // extern "C" fn.
        unsafe {
            narf_register_pci_driver(name.as_ptr(), name.len(), vendor, device, probe_c as usize);
        }
    }
}
