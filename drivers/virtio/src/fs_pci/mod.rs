//! virtio-fs over modern virtio-PCI transport (VirtIO 1.2 §5.11).
//!
//! Modern virtio-fs PCI device id: `0x1040 + 26 = 0x105A` (§4.1.2,
//! virtio device type 26).
//!
//! Stage layout:
//!   * stage 1 — PCI match-table entry + decode of the device-specific
//!     config struct (§5.11.4): `tag[36]: u8` + `num_request_queues: u32`
//!     little-endian. No virtqueue traffic.
//!   * stage 2 — FUSE-on-virtio wire-format builders for the 40-byte
//!     `fuse_in_header` (FUSE wire-protocol docs) plus a few opcodes
//!     (FUSE_INIT=26, FUSE_LOOKUP=1, FUSE_GETATTR=3, FUSE_READ=15,
//!     FUSE_RELEASE=18). No VFS wire-up.

pub mod config;
pub mod fuse;

mod tests;

pub use config::{
    decode_device_config, FsConfig, FS_TAG_LEN,
    VIRTIO_FS_PCI_DEVICE, VIRTIO_FS_PCI_VENDOR,
};
pub use fuse::{
    FuseInHeader, FuseOpcode, FUSE_IN_HEADER_LEN,
    FUSE_GETATTR, FUSE_INIT, FUSE_LOOKUP, FUSE_READ, FUSE_RELEASE,
};

/// Stage 1: register the PCI match-table entry. No probe body yet —
/// stage 1's smoke only validates that the registry contains our
/// VID:DID. A `probe` stub is wired so the registry call shape matches
/// `register_pci_driver` on sibling drivers.
pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-fs-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_FS_PCI_VENDOR,
            device: VIRTIO_FS_PCI_DEVICE,
        },
        probe: probe_stub,
    });
}

/// Stage 1 stub — no bring-up. Returns Ok so probe_all_pci doesn't
/// surface an error; the live transport bring-up lands in stage 3+.
fn probe_stub(
    _device: narf_bus::BusDevice,
    _cap:    narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) -> Result<(), narf_bus::ProbeError> {
    Ok(())
}
