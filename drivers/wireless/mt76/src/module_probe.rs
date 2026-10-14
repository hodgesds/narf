//! Loadable-module registration path for mt76.
//!
//! Registration-only: the probe thunk returns `-ENOSYS` because the wireless
//! datapath ABI (MCU mailbox, WFDMA rings, netdev/wiphy registration) is not
//! yet exported across the module boundary. The built-in build registers the
//! full id table and the real `WirelessNetIface` scaffold; this registers the
//! primary MT7922 id as the module-build proof. See `drivers/net/i40e/` for
//! the rationale.

/// MediaTek PCI vendor id (`MTK_VENDOR`).
const VENDOR: u16 = 0x14c3;
/// MT7922 device id (`MTK_DEV_MT7922`), the headline CONNAC2 part.
const DEVICE: u16 = 0x7922;

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
    // -ENOSYS: datapath ABI not yet exported for the module build.
    -38
}

pub fn register() {
    const NAME: &[u8] = b"mt76-mt7922";
    // SAFETY: `NAME` is 'static; `probe_c` is a valid extern "C" fn.
    unsafe {
        narf_register_pci_driver(NAME.as_ptr(), NAME.len(), VENDOR, DEVICE, probe_c as usize);
    }
}
