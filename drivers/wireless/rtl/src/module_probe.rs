//! Loadable-module registration path for the legacy Realtek family
//! (multi-bus: rtl8xxxu USB + rtlwifi PCIe).
//!
//! Registration-only: the probe thunk returns `-ENOSYS` because the Wi-Fi
//! device datapath ABI is not yet exported. The built-in build registers the
//! rtl8xxxu USB class matches (`RTL8XXXU_USB_IDS`) and the rtlwifi PCIe id
//! table (`rtlwifi::regs::ALL_DEV_IDS`) and drives the native transport; this
//! registers the same ids as the module-build proof, through the
//! `narf_register_usb_driver` and `narf_register_pci_driver` KSYMTAB exports.
//!
//! A module build links ONLY those two imports — no kernel crates — so the
//! `.ko`'s undefined-symbol set stays within the exported ABI (xtask's `nm -u`
//! gate enforces it).

/// `usb_device_id` VID/PID match (`narf_bus::module_usb::MATCH_VENDOR_PRODUCT`).
const MATCH_VENDOR_PRODUCT: u16 = 1 << 0;

/// rtl8xxxu Realtek USB VID/PIDs (`narf_drivers_wireless_rtl_usb::
/// RTL8XXXU_USB_IDS`): Realtek-vendor primaries plus the rebranded
/// (TP-Link/D-Link/ASUS/Edimax/…) dongles.
const USB_IDS: &[(u16, u16)] = &[
    (0x2357, 0x0108),
    (0x2357, 0x0109),
    (0x2357, 0x010C),
    (0x2357, 0x0111),
    (0x2357, 0x0107),
    (0x2357, 0x0126),
    (0x2019, 0xAB33),
    (0x2001, 0x3312),
    (0x2C4E, 0x0100),
    (0x2C4E, 0x0104),
    (0x2001, 0x3319),
    (0x2001, 0x3311),
    (0x7392, 0xB811),
    (0x7392, 0xA611),
    (0x0B05, 0x18F0),
    (0x07B8, 0x8179),
];

/// Realtek PCI vendor (`rtlwifi::regs::REALTEK_VENDOR`).
const REALTEK_VENDOR: u16 = 0x10EC;
/// rtlwifi PCIe ids (`rtlwifi::regs::ALL_DEV_IDS`): RTL8188EE/8192CE/8192DE/
/// 8192EE/8723AE/8723BE/8821AE.
const PCI_DIDS: &[u16] = &[
    0x8179, 0x8178, 0x8176, 0x8177, 0x8191, 0x8193, 0x818B, 0x8723, 0xB723, 0x8821,
];

unsafe extern "C" {
    #[allow(clippy::too_many_arguments)]
    fn narf_register_usb_driver(
        name: *const u8,
        name_len: usize,
        match_flags: u16,
        vendor: u16,
        product: u16,
        class: u8,
        subclass: u8,
        protocol: u8,
        probe: usize,
    ) -> i32;
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
    const USB_NAME: &[u8] = b"rtl8xxxu-module";
    for &(vendor, product) in USB_IDS {
        // SAFETY: `USB_NAME` is 'static; `probe_c` is a valid extern "C" fn;
        // the loader unregisters every match before unmapping this image.
        unsafe {
            narf_register_usb_driver(
                USB_NAME.as_ptr(),
                USB_NAME.len(),
                MATCH_VENDOR_PRODUCT,
                vendor,
                product,
                0,
                0,
                0,
                probe_c as usize,
            );
        }
    }
    const PCI_NAME: &[u8] = b"rtlwifi-module";
    for &device in PCI_DIDS {
        // SAFETY: `PCI_NAME` is 'static; `probe_c` is a valid extern "C" fn;
        // the loader unregisters every match before unmapping this image.
        unsafe {
            narf_register_pci_driver(
                PCI_NAME.as_ptr(),
                PCI_NAME.len(),
                REALTEK_VENDOR,
                device,
                probe_c as usize,
            );
        }
    }
}
