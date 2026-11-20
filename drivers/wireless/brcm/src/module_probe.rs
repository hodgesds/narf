//! Loadable-module registration path for the Broadcom/Infineon FullMAC family
//! (multi-bus: brcmfmac PCIe + CYW43439 SDIO).
//!
//! Registration-only: the probe thunk returns `-ENOSYS` because the Wi-Fi
//! device datapath ABI is not yet exported. The built-in build registers the
//! brcmfmac PCIe id table (`brcmfmac::pcie::ALL_DEV_IDS`) and the CYW43439 SDIO
//! function matches (`cyw43439::bootstrap::register`) and drives the native
//! transport; this registers the same ids as the module-build proof, through
//! the `narf_register_pci_driver` and `narf_register_sdio_driver` KSYMTAB
//! exports.
//!
//! A module build links ONLY those two imports — no kernel crates — so the
//! `.ko`'s undefined-symbol set stays within the exported ABI (xtask's `nm -u`
//! gate enforces it).

/// Broadcom PCIe vendor (`brcmfmac::pcie::BROADCOM_VENDOR`).
const BROADCOM_VENDOR: u16 = 0x14E4;

/// brcmfmac PCIe ids (`brcmfmac::pcie::ALL_DEV_IDS`): the full Broadcom FullMAC
/// PCIe table (BCM4350..BCM4387).
const PCI_DIDS: &[u16] = &[
    0x43A3, 0x43DF, 0x4354, 0x43DC, 0x43EC, 0x43D3, 0x43D9, 0xAA31, 0x43E9, 0x43EF, 0x43BA, 0x43BB,
    0x43BC, 0x4464, 0x43CA, 0x43CB, 0x43CC, 0x43C3, 0x43C4, 0x43C5, 0x440D, 0x4415, 0x449D, 0x4488,
    0x4425, 0x4433,
];

/// CYW43439 SDIO function-1 matches (`cyw43439::bootstrap::register`): the
/// Infineon and the Cypress-branded (vendor, device) pairs.
const SDIO_IDS: &[(&str, u16, u16)] = &[
    ("cyw43439-sdio-module", 0x02D0, 0xA9AF),
    ("cyw43439-cypress-sdio-module", 0x04B4, 0xBD3D),
];
/// The combo chip's WLAN function is F1 (backplane); F2 is the data FIFO.
const SDIO_FUNCTION: u8 = 1;

unsafe extern "C" {
    fn narf_register_pci_driver(
        name: *const u8,
        name_len: usize,
        vendor: u16,
        device: u16,
        probe: usize,
    ) -> i32;
    fn narf_register_sdio_driver(
        name: *const u8,
        name_len: usize,
        vendor: u16,
        device: u16,
        function: u8,
        probe: usize,
    ) -> i32;
}

extern "C" fn probe_c(_dev_token: u64, _reserved: u64) -> i32 {
    // -ENOSYS: the Wi-Fi device datapath ABI is not yet exported.
    -38
}

pub fn register() {
    const PCI_NAME: &[u8] = b"brcmfmac-module";
    for &device in PCI_DIDS {
        // SAFETY: `PCI_NAME` is 'static; `probe_c` is a valid extern "C" fn.
        // The loader unregisters every match before unmapping this image.
        unsafe {
            narf_register_pci_driver(
                PCI_NAME.as_ptr(),
                PCI_NAME.len(),
                BROADCOM_VENDOR,
                device,
                probe_c as usize,
            );
        }
    }
    for &(name, vendor, device) in SDIO_IDS {
        // SAFETY: `name` is 'static; `probe_c` is a valid extern "C" fn; the
        // loader unregisters the match before unmapping this image.
        unsafe {
            narf_register_sdio_driver(
                name.as_ptr(),
                name.len(),
                vendor,
                device,
                SDIO_FUNCTION,
                probe_c as usize,
            );
        }
    }
}
