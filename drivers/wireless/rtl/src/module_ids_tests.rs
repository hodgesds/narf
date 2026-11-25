//! `module_ids` against the drivers' own id tables.

use super::module_ids::{PCI_DEVICES, PCI_VENDOR, USB_IDS};

fn smoke_rtl_module_ids_match_driver_tables() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    if PCI_VENDOR != crate::rtlwifi::regs::REALTEK_VENDOR
        || PCI_DEVICES != crate::rtlwifi::regs::ALL_DEV_IDS
    {
        return TestResult::Fail("rtl.ko PCI table differs from rtlwifi::regs::ALL_DEV_IDS");
    }
    let shared = narf_drivers_wireless_rtl_usb::RTL8XXXU_USB_IDS;
    if shared.len() != USB_IDS.len()
        || !shared
            .iter()
            .zip(USB_IDS)
            .all(|(m, &(vid, pid))| m.vendor_id == vid && m.product_id == pid)
    {
        return TestResult::Fail("rtl.ko USB table differs from RTL8XXXU_USB_IDS");
    }
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!(
    "drivers/wireless/rtlwifi/module",
    smoke_rtl_module_ids_match_driver_tables
);
