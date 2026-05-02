//! virtio-9p (transitional / legacy) PCI driver — clean room.
//!
//! VirtIO 1.2 §5.9 ("9P transport") describes the device-specific
//! configuration; the wire protocol is Plan 9 9P2000.L
//! (https://ericvh.github.io/9p-rfc/rfc9p2000.l.html).
//!
//! Stage 1: PCI match + pure-data mount-tag decode.
//! Stage 2: 9P2000.L message builders (pure-data encode/decode).

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

// ── PCI ids ────────────────────────────────────────────────────────

/// virtio-9p PCI vendor id (Red Hat).
pub const VIRTIO_9P_PCI_VENDOR: u16 = 0x1AF4;
/// virtio-9p legacy / transitional PCI device id (VirtIO 1.2 §4.1.2.1).
pub const VIRTIO_9P_PCI_DEVICE: u16 = 0x1009;

// ── §5.9.4 device-specific configuration ───────────────────────────

/// Decoded virtio-9p device-config layout (VirtIO 1.2 §5.9.4):
///   `mount_tag_len: u16 LE`
///   `mount_tag:     [u8; mount_tag_len]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountTag {
    pub tag: Vec<u8>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MountTagDecodeError {
    TooShortForLen,
    TooShortForTag,
}

impl MountTag {
    /// Decode the device-specific config region. Reads
    /// `mount_tag_len` (u16 LE) then the following `mount_tag_len`
    /// bytes of UTF-8-ish tag.
    pub fn decode(buf: &[u8]) -> Result<Self, MountTagDecodeError> {
        if buf.len() < 2 { return Err(MountTagDecodeError::TooShortForLen); }
        let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        if buf.len() < 2 + len { return Err(MountTagDecodeError::TooShortForTag); }
        let mut tag = Vec::with_capacity(len);
        tag.extend_from_slice(&buf[2..2 + len]);
        Ok(Self { tag })
    }

    /// Encode back to wire form (used by smokes for round-trip).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.tag.len());
        let len = self.tag.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.tag);
        out
    }
}

// ── PCI driver registration ────────────────────────────────────────

pub fn probe(
    _device: narf_bus::BusDevice,
    _cap:    narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) -> Result<(), narf_bus::ProbeError> {
    // Stage 1/2 are pure-data; no device bring-up here. The match
    // table entry exists so probe_all_pci's enumeration sees the
    // driver, but the probe is a no-op until stage 3 lands the
    // virtqueue path.
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-9p-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_9P_PCI_VENDOR,
            device: VIRTIO_9P_PCI_DEVICE,
        },
        probe,
    });
}

// ── 9P2000.L wire protocol (stage 2) ───────────────────────────────

pub mod p9;

mod tests;
