//! Intel VSEC — the PMT (Platform Monitoring Technology) discovery
//! function: telemetry, watcher, and crashlog.
//!
//! ## Reference
//!
//! Linux v7.3-rc4 (GPL-2.0; NARF is GPL-2.0-or-later so adaptation
//! is permitted):
//!
//! - `drivers/platform/x86/intel/vsec.c` — PCI ids, per-SKU
//!   capability masks, `intel_vsec_walk_dvsec` / `intel_vsec_walk_vsec`.
//! - `include/linux/intel_vsec.h` — `struct intel_vsec_header`, the
//!   `INTEL_DVSEC_*` offsets, `VSEC_CAP_*`.
//!
//! ## Hardware this targets
//!
//! The Minisforum **MS-03** exposes this function at PCI `00:0a.0`
//! (`8086:b07d`, "Crashlog and Telemetry"). Linux calls it
//! `PCI_DEVICE_ID_INTEL_VSEC_PTL`.
//!
//! ## What the device is
//!
//! The function itself has no fixed register map. What it carries is
//! a list of **extended capabilities** in config space, each of which
//! names a feature (telemetry, crashlog, …) and points at a discovery
//! table somewhere in one of the function's BARs. The layout is
//! published two ways, and a given part may use either:
//!
//! - **DVSEC** (extended cap `0x0023`), whose header carries the
//!   vendor id, revision and length, with the feature id in a second
//!   header dword; and
//! - **VSEC** (extended cap `0x000B`), whose single header dword
//!   carries id, revision and length together.
//!
//! Both then use the *same* three fields at `+0xA`, `+0xB` and `+0xC`
//! for entry count, entry size, and the packed BAR-index / offset of
//! the discovery table. This module walks both lists and records what
//! it finds.
//!
//! ## Scope
//!
//! Discovery only: enumerate the capabilities, decode each header,
//! and record which features the part advertises. Mapping the
//! discovery tables, decoding telemetry sample descriptors, and
//! pulling a crashlog are **not** implemented — those want a
//! consumer, and there isn't one in tree yet. What is here is enough
//! to answer "what does this silicon expose", which is exactly what
//! the boot transcript and a future consumer both need first.

extern crate alloc;

use alloc::vec::Vec;

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

// ── PCI device IDs ──────────────────────────────────────────────────
//
// Linux `vsec.c`.

/// Intel.
pub const VSEC_VENDOR: u16 = 0x8086;

/// Tiger Lake — `PCI_DEVICE_ID_INTEL_VSEC_TGL`.
pub const VSEC_DEV_TGL: u16 = 0x9A0D;
/// Alder Lake — `PCI_DEVICE_ID_INTEL_VSEC_ADL`.
pub const VSEC_DEV_ADL: u16 = 0x467D;
/// Raptor Lake — `PCI_DEVICE_ID_INTEL_VSEC_RPL`.
pub const VSEC_DEV_RPL: u16 = 0xA77D;
/// Meteor Lake-M — `PCI_DEVICE_ID_INTEL_VSEC_MTL_M`.
pub const VSEC_DEV_MTL_M: u16 = 0x7D0D;
/// Meteor Lake-S — `PCI_DEVICE_ID_INTEL_VSEC_MTL_S`.
pub const VSEC_DEV_MTL_S: u16 = 0xAD0D;
/// Lunar Lake-M — `PCI_DEVICE_ID_INTEL_VSEC_LNL_M`.
pub const VSEC_DEV_LNL_M: u16 = 0x647D;
/// Panther Lake — `PCI_DEVICE_ID_INTEL_VSEC_PTL`. The MS-03's
/// `00:0a.0`.
pub const VSEC_DEV_PTL: u16 = 0xB07D;
/// Wildcat Lake — `PCI_DEVICE_ID_INTEL_VSEC_WCL`.
pub const VSEC_DEV_WCL: u16 = 0xFD7D;
/// Nova Lake — `PCI_DEVICE_ID_INTEL_VSEC_NVL`.
pub const VSEC_DEV_NVL: u16 = 0xD70D;

/// Every device ID this driver claims.
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    VSEC_DEV_TGL,
    VSEC_DEV_ADL,
    VSEC_DEV_RPL,
    VSEC_DEV_MTL_M,
    VSEC_DEV_MTL_S,
    VSEC_DEV_LNL_M,
    VSEC_DEV_PTL,
    VSEC_DEV_WCL,
    VSEC_DEV_NVL,
];

/// `true` iff this driver claims `did`.
pub fn is_supported_device(did: u16) -> bool {
    SUPPORTED_DEVICE_IDS.contains(&did)
}

// ── Capability bits ─────────────────────────────────────────────────
//
// `VSEC_CAP_*`. Bit 0 is deliberately unused so a zero-initialised
// device is not mistaken for "has capability id 0".

/// Reserved; never a real capability.
pub const VSEC_CAP_UNUSED: u32 = 1 << 0;
/// Telemetry aggregator.
pub const VSEC_CAP_TELEMETRY: u32 = 1 << 1;
/// Watcher.
pub const VSEC_CAP_WATCHER: u32 = 1 << 2;
/// Crashlog.
pub const VSEC_CAP_CRASHLOG: u32 = 1 << 3;
/// Software-defined silicon.
pub const VSEC_CAP_SDSI: u32 = 1 << 4;
/// Topology-aware register interface.
pub const VSEC_CAP_TPMI: u32 = 1 << 5;
/// Discovery.
pub const VSEC_CAP_DISCOVERY: u32 = 1 << 6;

/// Capability mask Linux's platform info declares for `did`.
///
/// This is what the *driver* is willing to attach to, not what the
/// silicon reports — the authoritative list comes from the capability
/// walk in [`VsecDevice::features`].
pub const fn platform_caps_for(did: u16) -> u32 {
    match did {
        // `tgl_info`
        VSEC_DEV_TGL | VSEC_DEV_ADL | VSEC_DEV_RPL => VSEC_CAP_TELEMETRY,
        // `mtl_info`, which Panther Lake / Wildcat Lake / Nova Lake
        // also use.
        VSEC_DEV_MTL_M | VSEC_DEV_MTL_S | VSEC_DEV_PTL | VSEC_DEV_WCL | VSEC_DEV_NVL => {
            VSEC_CAP_TELEMETRY
        }
        // `lnl_info`
        VSEC_DEV_LNL_M => VSEC_CAP_TELEMETRY | VSEC_CAP_WATCHER,
        _ => 0,
    }
}

// ── Extended-capability layout ──────────────────────────────────────

/// PCIe extended capability ID for a Designated Vendor-Specific
/// Extended Capability. `PCI_EXT_CAP_ID_DVSEC`.
pub const EXT_CAP_ID_DVSEC: u16 = 0x0023;
/// PCIe extended capability ID for a Vendor-Specific Extended
/// Capability. `PCI_EXT_CAP_ID_VNDR`.
pub const EXT_CAP_ID_VNDR: u16 = 0x000B;

/// `PCI_DVSEC_HEADER1` — offset of the first DVSEC header dword from
/// the start of the capability.
pub const DVSEC_HEADER1: u16 = 0x04;
/// `PCI_DVSEC_HEADER2` — offset of the second DVSEC header dword.
pub const DVSEC_HEADER2: u16 = 0x08;
/// `PCI_VNDR_HEADER` — offset of the single VSEC header dword.
pub const VNDR_HEADER: u16 = 0x04;

/// `INTEL_DVSEC_ENTRIES` — entry count, one byte. Shared by both the
/// DVSEC and VSEC layouts.
pub const INTEL_DVSEC_ENTRIES: u16 = 0x0A;
/// `INTEL_DVSEC_SIZE` — per-entry size, one byte.
pub const INTEL_DVSEC_SIZE: u16 = 0x0B;
/// `INTEL_DVSEC_TABLE` — packed BAR index + table offset, one dword.
pub const INTEL_DVSEC_TABLE: u16 = 0x0C;

/// `INTEL_DVSEC_TABLE_BAR` — bits 2:0 of the table dword are the BAR
/// index the discovery table lives in.
pub const fn table_bar(table: u32) -> u8 {
    (table & 0x7) as u8
}

/// `INTEL_DVSEC_TABLE_OFFSET` — bits 31:3 are the byte offset of the
/// table within that BAR. The low three bits are the BAR index, so
/// the offset is inherently 8-byte aligned and is **not** shifted
/// down.
pub const fn table_offset(table: u32) -> u32 {
    table & !0x7
}

/// Decoded header of one VSEC / DVSEC capability —
/// `struct intel_vsec_header`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct VsecHeader {
    /// Revision of the capability's register space. Linux supports
    /// only revision 1.
    pub rev: u8,
    /// Length of the capability's register space.
    pub length: u16,
    /// Feature id — which `VSEC_CAP_*` this entry describes.
    pub id: u16,
    /// Number of instances of the feature.
    pub num_entries: u8,
    /// Size of each instance's discovery table.
    pub entry_size: u8,
    /// BAR index the discovery tables live in.
    pub tbir: u8,
    /// Byte offset of the first discovery table within that BAR.
    pub offset: u32,
    /// Config-space offset the capability itself was found at.
    pub cap_offset: u64,
    /// Which list this came from.
    pub kind: VsecKind,
}

/// Which extended-capability list a header was found in.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum VsecKind {
    /// Designated Vendor-Specific (`0x0023`).
    #[default]
    Dvsec,
    /// Vendor-Specific (`0x000B`).
    Vndr,
}

/// `PCI_DVSEC_HEADER1_VID` — vendor id, bits 15:0.
pub const fn dvsec_header1_vid(hdr: u32) -> u16 {
    (hdr & 0xFFFF) as u16
}
/// `PCI_DVSEC_HEADER1_REV` — revision, bits 19:16.
pub const fn dvsec_header1_rev(hdr: u32) -> u8 {
    ((hdr >> 16) & 0xF) as u8
}
/// `PCI_DVSEC_HEADER1_LEN` — length, bits 31:20.
pub const fn dvsec_header1_len(hdr: u32) -> u16 {
    ((hdr >> 20) & 0xFFF) as u16
}
/// `PCI_DVSEC_HEADER2_ID` — feature id, bits 15:0.
pub const fn dvsec_header2_id(hdr: u32) -> u16 {
    (hdr & 0xFFFF) as u16
}

/// `PCI_VNDR_HEADER_ID` — feature id, bits 15:0.
pub const fn vndr_header_id(hdr: u32) -> u16 {
    (hdr & 0xFFFF) as u16
}
/// `PCI_VNDR_HEADER_REV` — revision, bits 19:16.
pub const fn vndr_header_rev(hdr: u32) -> u8 {
    ((hdr >> 16) & 0xF) as u8
}
/// `PCI_VNDR_HEADER_LEN` — length, bits 31:20.
pub const fn vndr_header_len(hdr: u32) -> u16 {
    ((hdr >> 20) & 0xFFF) as u16
}

/// The only capability-space revision Linux (and this driver)
/// understands.
pub const SUPPORTED_REVISION: u8 = 1;

/// Map a feature id to its `VSEC_CAP_*` bit. The id *is* the bit
/// index — Linux does `BIT(header->id)` — so id 1 is telemetry, id 3
/// is crashlog, and so on. Ids past bit 6 have no name yet.
pub const fn cap_bit_for_id(id: u16) -> u32 {
    if id >= 32 {
        0
    } else {
        1u32 << id
    }
}

/// Human-readable name for a feature id.
pub const fn feature_name(id: u16) -> &'static str {
    match cap_bit_for_id(id) {
        VSEC_CAP_TELEMETRY => "telemetry",
        VSEC_CAP_WATCHER => "watcher",
        VSEC_CAP_CRASHLOG => "crashlog",
        VSEC_CAP_SDSI => "sdsi",
        VSEC_CAP_TPMI => "tpmi",
        VSEC_CAP_DISCOVERY => "discovery",
        _ => "unknown",
    }
}

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VsecError {
    /// The extended-capability list could not be walked.
    CapWalkFailed,
    /// Neither list held a usable Intel capability.
    NoCapabilities,
}

// ── Live driver state ───────────────────────────────────────────────

/// A probed VSEC/PMT function and everything its capability lists
/// advertise.
#[derive(Debug)]
pub struct VsecDevice {
    /// PCI device id.
    pub device_id: u16,
    /// Capability mask Linux's platform info declares for this SKU.
    pub platform_caps: u32,
    /// Every capability header found, in list order.
    pub headers: Vec<VsecHeader>,
}

impl VsecDevice {
    /// Bitmask of the `VSEC_CAP_*` features the silicon actually
    /// advertised, as opposed to the per-SKU list in
    /// [`platform_caps_for`].
    pub fn features(&self) -> u32 {
        self.headers
            .iter()
            .map(|h| cap_bit_for_id(h.id))
            .fold(0, |a, b| a | b)
    }

    /// `true` if the silicon advertised `feature`.
    pub fn has_feature(&self, feature: u32) -> bool {
        self.features() & feature == feature
    }

    /// The header for `feature`, if the walk found one.
    pub fn header_for(&self, feature: u32) -> Option<&VsecHeader> {
        self.headers
            .iter()
            .find(|h| cap_bit_for_id(h.id) == feature)
    }
}

/// Walk both extended-capability lists and decode every Intel entry.
fn walk_capabilities(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
) -> Result<Vec<VsecHeader>, VsecError> {
    let read_cap: Cap<BusDeviceCap, narf_capabilities::Read> =
        cap.derive().map_err(|_| VsecError::CapWalkFailed)?;
    let mut out = Vec::new();

    for hdr in
        narf_bus::pci_cap_ext::iter(&read_cap, device).map_err(|_| VsecError::CapWalkFailed)?
    {
        let base = hdr.offset as u16;
        let kind = match hdr.id {
            EXT_CAP_ID_DVSEC => VsecKind::Dvsec,
            EXT_CAP_ID_VNDR => VsecKind::Vndr,
            _ => continue,
        };

        let (rev, length, id) = match kind {
            VsecKind::Dvsec => {
                let h1 = read_cfg32(cap, device, base + DVSEC_HEADER1);
                // A DVSEC belonging to some other vendor on the same
                // function is not ours to decode.
                if dvsec_header1_vid(h1) != VSEC_VENDOR {
                    continue;
                }
                let h2 = read_cfg32(cap, device, base + DVSEC_HEADER2);
                (
                    dvsec_header1_rev(h1),
                    dvsec_header1_len(h1),
                    dvsec_header2_id(h2),
                )
            }
            VsecKind::Vndr => {
                let h = read_cfg32(cap, device, base + VNDR_HEADER);
                (vndr_header_rev(h), vndr_header_len(h), vndr_header_id(h))
            }
        };

        // Linux supports only revision 1 and skips anything else
        // rather than guessing at a layout it does not know.
        if rev != SUPPORTED_REVISION {
            continue;
        }

        // Entries / size / table are at the same three offsets in
        // both layouts. They are byte-wide fields inside dwords, so
        // they are extracted from the containing aligned read.
        let entries_dword = read_cfg32(cap, device, base + (INTEL_DVSEC_ENTRIES & !3));
        let entries_shift = ((INTEL_DVSEC_ENTRIES & 3) * 8) as u32;
        let num_entries = ((entries_dword >> entries_shift) & 0xFF) as u8;
        let size_shift = ((INTEL_DVSEC_SIZE & 3) * 8) as u32;
        let entry_size = ((entries_dword >> size_shift) & 0xFF) as u8;

        let table = read_cfg32(cap, device, base + INTEL_DVSEC_TABLE);

        out.push(VsecHeader {
            rev,
            length,
            id,
            num_entries,
            entry_size,
            tbir: table_bar(table),
            offset: table_offset(table),
            cap_offset: hdr.offset,
            kind,
        });
    }

    if out.is_empty() {
        return Err(VsecError::NoCapabilities);
    }
    Ok(out)
}

fn read_cfg32(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice, offset: u16) -> u32 {
    narf_bus::pci::read_config32(cap, device, offset).unwrap_or(0)
}

// ── Driver-match registration ───────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<alloc::sync::Arc<VsecDevice>>> =
    IrqSafeSpinLock::new(None);

/// Probe entry — installed via `bus::register_pci_driver`.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if device.id.vendor != VSEC_VENDOR || !is_supported_device(device.id.device) {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    let headers = match walk_capabilities(&cap, &device) {
        Ok(h) => h,
        Err(e) => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  intel_vsec: capability walk failed on {:04x}: {:?}",
                device.id.device,
                e,
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };

    let dev = VsecDevice {
        device_id: device.id.device,
        platform_caps: platform_caps_for(device.id.device),
        headers,
    };

    {
        use core::fmt::Write as _;
        let _ = write!(
            narf_console::Writer,
            "  intel_vsec: {:04x} {} capabilities:",
            dev.device_id,
            dev.headers.len(),
        );
        for h in &dev.headers {
            let _ = write!(
                narf_console::Writer,
                " {}(bar{}+{:#x}, {}x{})",
                feature_name(h.id),
                h.tbir,
                h.offset,
                h.num_entries,
                h.entry_size,
            );
        }
        let _ = writeln!(narf_console::Writer);
    }

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("intel_vsec"),
        kind: narf_drivers::BoundKind::Other,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Other.default_domain(),
    });

    *CONTROLLER.lock() = Some(alloc::sync::Arc::new(dev));
    Ok(())
}

/// Register the VSEC PCI driver — one match entry per device ID.
pub fn register_pci_driver() {
    for did in SUPPORTED_DEVICE_IDS.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: "intel_vsec",
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: VSEC_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// `true` once a VSEC function has been probed.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Run `f` against the probed VSEC function, if any.
pub fn with_device<R>(f: impl FnOnce(&VsecDevice) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(|a| f(a))
}

#[doc(hidden)]
/// Test-only: forget the probed device so a smoke can assert
/// end-state.
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}
