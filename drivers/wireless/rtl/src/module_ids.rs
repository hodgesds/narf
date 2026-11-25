//! The id tables `rtl.ko` registers.
//!
//! Self-contained (no crate paths) on purpose: `modules/src/tests_e2e.rs`
//! includes this file to check the loaded module claims exactly these rows,
//! and a built-in kernel test (`module_ids_tests.rs`) pins both tables to the
//! driver's own (`rtlwifi::regs::ALL_DEV_IDS`, `RTL8XXXU_USB_IDS`), so
//! neither copy can drift.

/// Realtek PCI vendor (`rtlwifi::regs::REALTEK_VENDOR`).
pub const PCI_VENDOR: u16 = 0x10EC;

/// rtlwifi PCIe device ids, `rtlwifi/pci.c` `rtl_pci_id_tbl` order
/// (`rtlwifi::regs::ALL_DEV_IDS`): RTL8188EE, the four RTL8192CE ids,
/// RTL8192DE, RTL8192EE, RTL8723AE, RTL8723BE, RTL8821AE. RTL8822BE
/// (`0xB822`) is rtw88's.
pub const PCI_DEVICES: &[u16] = &[
    0x8179, 0x8178, 0x8176, 0x8177, 0x8191, 0x8193, 0x818B, 0x8723, 0xB723, 0x8821,
];

/// rtl8xxxu USB VID/PIDs, `RTL8XXXU_USB_IDS` order: the Realtek-vendor
/// primaries, then the rebranded (TP-Link, D-Link, Edimax, ASUS, Abocom)
/// dongles. RTL8821CU / RTL8822BU are rtw88's and are not listed.
pub const USB_IDS: &[(u16, u16)] = &[
    (0x0BDA, 0x8179),
    (0x0BDA, 0x0179),
    (0x0BDA, 0x818B),
    (0x0BDA, 0x818C),
    (0x0BDA, 0xB720),
    (0x0BDA, 0xB711),
    (0x0BDA, 0xFFEF),
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
