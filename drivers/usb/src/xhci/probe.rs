//! PCI probe helpers for xHCI host controllers.
//!
//! The PCI class triple for an xHCI controller is `0x0C / 0x03 / 0x30`
//! (Serial Bus Controller / USB / xHCI). This module exposes the
//! constants + helpers for matching that triple.

#![allow(dead_code)]

/// PCI Base Class for Serial Bus Controllers.
pub const PCI_CLASS_SERIAL_BUS: u8 = 0x0C;
/// PCI Sub-Class for USB controllers.
pub const PCI_SUBCLASS_USB: u8 = 0x03;
/// PCI Prog-IF for xHCI.
pub const PCI_PROGIF_XHCI: u8 = 0x30;

/// Packed 24-bit class code (Class << 16 | Subclass << 8 | Prog-IF).
/// The standard PCI lspci notation: `0c0330`.
pub const PCI_CLASS_TRIPLE_XHCI: u32 = ((PCI_CLASS_SERIAL_BUS as u32) << 16)
    | ((PCI_SUBCLASS_USB as u32) << 8)
    | (PCI_PROGIF_XHCI as u32);

/// Return true if `class_triple` matches an xHCI controller.
pub const fn is_xhci_class(class_triple: u32) -> bool {
    (class_triple & 0x00FF_FFFF) == PCI_CLASS_TRIPLE_XHCI
}

// Re-export the PCI driver registration entry point + the
// `is_probed` / `controller` accessors so callers can see the full
// surface from `xhci::probe`.
pub use super::{controller, is_probed, register_pci_driver, IS_PROBED};
