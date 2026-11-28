//! Loadable-module registration path for the Realtek rtw88/rtw89 family.
//!
//! Registration-only: the probe thunk returns `-ENOSYS` because the Wi-Fi
//! device datapath ABI is not yet exported. The built-in build registers the
//! full id tables and drives the native transport; this registers the same
//! Realtek ids as the module-build proof. See `narf-drivers-net-tg3` for the
//! registration-only shape.
//!
//! A module build links ONLY the `narf_register_pci_driver` KSYMTAB import —
//! no kernel crates — so the `.ko`'s undefined-symbol set stays within the
//! exported ABI (cargo narf's `nm -u` gate enforces it).

/// Realtek.
const REALTEK_VENDOR: u16 = 0x10EC;

/// rtw88 PCIe ids (`rtw88::regs::ALL_DEV_IDS`): RTL8821CE/8822CE/8822BE.
const RTW88_DIDS: &[u16] = &[0xC821, 0xC822, 0xB822];

/// rtw89 PCIe ids (`rtw89::ALL_DEV_IDS`): RTL8852AE/8852AE_VT/8852BE/
/// 8852BE_ALT/8852CE/8851BE/8922AE/8922AE_ALT.
const RTW89_DIDS: &[u16] = &[
    0x8852, 0xA85A, 0xB852, 0xB85B, 0xC852, 0xB851, 0x8922, 0x892B,
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
    for &(name, dids) in &[
        (b"rtw88-module".as_slice(), RTW88_DIDS),
        (b"rtw89-module".as_slice(), RTW89_DIDS),
    ] {
        for &device in dids {
            // SAFETY: `name` is 'static; `probe_c` is a valid extern "C" fn.
            // The loader unregisters every match before unmapping this image.
            unsafe {
                narf_register_pci_driver(
                    name.as_ptr(),
                    name.len(),
                    REALTEK_VENDOR,
                    device,
                    probe_c as usize,
                );
            }
        }
    }
}
