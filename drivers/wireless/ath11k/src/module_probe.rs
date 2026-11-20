//! Loadable-module registration path for ath11k (multi-bus: PCI + DT/AHB).
//!
//! Registration-only: the probe thunk returns `-ENOSYS` because the Wi-Fi
//! device datapath ABI is not yet exported. The built-in build registers the
//! PCI id table (`ath11k::hw::ALL_DEV_IDS`) and the AHB DT match table
//! (`ath11k::ahb::AHB_OF_MATCH`) and drives the native transport; this
//! registers the same ids/compatibles as the module-build proof, through the
//! `narf_register_pci_driver` and `narf_register_dt_driver` KSYMTAB exports.
//!
//! A module build links ONLY those two imports — no kernel crates — so the
//! `.ko`'s undefined-symbol set stays within the exported ABI (xtask's `nm -u`
//! gate enforces it).

/// Qualcomm.
const QCOM_VENDOR: u16 = 0x17cb;
/// PCIe device ids (`ath11k::hw::ALL_DEV_IDS`): QCA6390 / WCN6855 / QCN9074.
const PCI_DIDS: &[u16] = &[0x1101, 0x1103, 0x1104];
/// AHB Devicetree matches: a unique registry name paired with each
/// `ath11k::ahb::AHB_OF_MATCH` compatible string.
const DT_MATCHES: &[(&str, &str)] = &[
    ("ath11k-ahb-ipq8074", "qcom,ipq8074-wifi"),
    ("ath11k-ahb-ipq6018", "qcom,ipq6018-wifi"),
    ("ath11k-ahb-wcn6750", "qcom,wcn6750-wifi"),
    ("ath11k-ahb-ipq5018", "qcom,ipq5018-wifi"),
];

unsafe extern "C" {
    fn narf_register_pci_driver(
        name: *const u8,
        name_len: usize,
        vendor: u16,
        device: u16,
        probe: usize,
    ) -> i32;
    fn narf_register_dt_driver(
        name: *const u8,
        name_len: usize,
        compatible: *const u8,
        compatible_len: usize,
        probe: usize,
    ) -> i32;
}

extern "C" fn probe_c(_dev_token: u64, _reserved: u64) -> i32 {
    // -ENOSYS: the Wi-Fi device datapath ABI is not yet exported.
    -38
}

pub fn register() {
    const PCI_NAME: &[u8] = b"ath11k-module";
    for &device in PCI_DIDS {
        // SAFETY: `PCI_NAME` is 'static; `probe_c` is a valid extern "C" fn.
        // The loader unregisters every match before unmapping this image.
        unsafe {
            narf_register_pci_driver(
                PCI_NAME.as_ptr(),
                PCI_NAME.len(),
                QCOM_VENDOR,
                device,
                probe_c as usize,
            );
        }
    }
    for &(name, compatible) in DT_MATCHES {
        // SAFETY: `name`/`compatible` are 'static; `probe_c` is a valid
        // extern "C" fn; the loader unregisters the match before unmap.
        unsafe {
            narf_register_dt_driver(
                name.as_ptr(),
                name.len(),
                compatible.as_ptr(),
                compatible.len(),
                probe_c as usize,
            );
        }
    }
}
