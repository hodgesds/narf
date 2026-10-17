//! Namespace scan and disk identity — the host-side logic of Linux
//! `drivers/nvme/host/core.c` (`nvme_scan_work` → `nvme_scan_ns_list` /
//! `nvme_scan_ns_sequential` → `nvme_scan_ns`, `nvme_identify_ns_descs`,
//! and the `nvme_ns_head` identity `nvme_ns_ids`), kept free of hardware
//! access so the decode and naming rules are model-testable.
//!
//! # Names are not identity
//!
//! Block names follow Linux: controller `nvme<C>` in probe order (which is
//! PCI enumeration order), namespace `nvme<C>n<N>` where `N` counts the
//! controller's registered namespaces from 1 in ascending NSID order (Linux
//! numbers namespace heads per subsystem the same way), and partitions
//! `nvme<C>n<N>p<P>`. A controller that fails to probe, a disk moved to
//! another slot, or a firmware that reorders the bus all change names. The
//! stable identity is [`narf_block::DiskIdentity`] (controller PCI address,
//! model/serial, namespace EUI64/NGUID/UUID) and the on-disk filesystem
//! UUID / GPT PARTUUID.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_block::{BlockDeviceSync, DiskIdentity};

/// Namespace identifiers (`struct nvme_ns_ids`). All-zero values are
/// absent, as Linux `nvme_ns_ids_valid` treats them.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct NsIds {
    pub eui64: Option<[u8; 8]>,
    pub nguid: Option<[u8; 16]>,
    pub uuid: Option<[u8; 16]>,
}

fn nonzero<const N: usize>(b: &[u8]) -> Option<[u8; N]> {
    let a: [u8; N] = b.get(..N)?.try_into().ok()?;
    if a.iter().all(|&x| x == 0) {
        None
    } else {
        Some(a)
    }
}

/// NGUID (bytes 104..120) and EUI64 (bytes 120..128) of an Identify
/// Namespace page (NVM Command Set 1.0c Figure 97), as Linux
/// `nvme_ns_info_from_identify` copies them.
pub fn ids_from_identify_ns(id_ns: &[u8]) -> NsIds {
    NsIds {
        nguid: id_ns.get(104..120).and_then(nonzero::<16>),
        eui64: id_ns.get(120..128).and_then(nonzero::<8>),
        uuid: None,
    }
}

/// Namespace Identification Descriptor types (NVMe Base 2.0c Figure 274).
const NIDT_EUI64: u8 = 1;
const NIDT_NGUID: u8 = 2;
const NIDT_UUID: u8 = 3;

/// Decode a Namespace Identification Descriptor list (Identify CNS 0x03)
/// into `ids`, overriding what Identify Namespace reported. Mirrors Linux
/// `nvme_identify_ns_descs` / `nvme_process_ns_desc`: walk `{NIDT, NIDL,
/// rsvd[2], NID[NIDL]}` until a zero NIDL; a descriptor whose length does
/// not match its type ends the walk (the device is non-conformant), keeping
/// what was already decoded.
pub fn apply_ns_descriptors(list: &[u8], ids: &mut NsIds) {
    let mut pos = 0usize;
    while pos + 4 <= list.len() {
        let nidt = list[pos];
        let nidl = list[pos + 1] as usize;
        if nidl == 0 {
            break;
        }
        let Some(nid) = list.get(pos + 4..pos + 4 + nidl) else {
            break;
        };
        match (nidt, nidl) {
            (NIDT_EUI64, 8) => ids.eui64 = nonzero::<8>(nid).or(ids.eui64),
            (NIDT_NGUID, 16) => ids.nguid = nonzero::<16>(nid).or(ids.nguid),
            (NIDT_UUID, 16) => ids.uuid = nonzero::<16>(nid).or(ids.uuid),
            (NIDT_EUI64 | NIDT_NGUID | NIDT_UUID, _) => break,
            // CSI and later types: skip.
            _ => {}
        }
        pos += 4 + nidl;
    }
}

/// One active namespace NARF registers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NamespaceInfo {
    pub nsid: u32,
    /// Logical block size in bytes.
    pub lba_bytes: u32,
    /// NSZE in logical blocks.
    pub nsze: u64,
    /// False when the LBA format cannot carry block I/O (see
    /// `prp::NamespaceFormat::usable`). Such namespaces are not registered.
    pub usable: bool,
    pub ids: NsIds,
}

/// Why a scanned NSID is not registered.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NsSkip {
    /// NCAP = 0: allocated but not attached / inactive (Linux
    /// `nvme_ns_info_from_identify`: `!id->ncap` → `-ENODEV`).
    Inactive,
    /// NSZE = 0: nothing to address.
    ZeroCapacity,
    /// LBA format NARF cannot drive (Linux registers a zero-capacity disk).
    UnusableFormat,
}

/// Decide whether an Identify Namespace page describes a namespace to
/// register. `id_ns` must hold at least the first 384 bytes.
pub fn classify_namespace(nsid: u32, id_ns: &[u8]) -> Result<NamespaceInfo, NsSkip> {
    let fmt = super::prp::decode_namespace_format(id_ns);
    let ncap = id_ns
        .get(8..16)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0);
    if ncap == 0 {
        return Err(NsSkip::Inactive);
    }
    if fmt.nsze == 0 {
        return Err(NsSkip::ZeroCapacity);
    }
    if !fmt.usable {
        return Err(NsSkip::UnusableFormat);
    }
    Ok(NamespaceInfo {
        nsid,
        lba_bytes: fmt.lba_bytes,
        nsze: fmt.nsze,
        usable: true,
        ids: ids_from_identify_ns(id_ns),
    })
}

/// NVMe version at or above `major.minor`.
pub fn vs_at_least(vs: u32, major: u16, minor: u8) -> bool {
    vs >= ((major as u32) << 16) | ((minor as u32) << 8)
}

/// Linux `nvme_scan_work` uses the Active Namespace List (CNS 2) from
/// NVMe 1.1 on, and scans `1..=NN` sequentially before that.
pub fn use_ns_list(vs: u32) -> bool {
    vs_at_least(vs, 1, 1)
}

/// Linux `nvme_identify_ns_descs` asks for descriptors from NVMe 1.3 on.
pub fn use_ns_descriptors(vs: u32) -> bool {
    vs_at_least(vs, 1, 3)
}

/// Upper bound on NSIDs scanned per controller (sequential scan and the
/// list walk alike); the list walk pages 1024 at a time.
pub const MAX_SCANNED_NSIDS: u32 = 1024;

/// Decode one Active Namespace List page: ascending NSIDs, zero-terminated.
pub fn decode_ns_list(page: &[u8]) -> Vec<u32> {
    page.chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .take_while(|&n| n != 0)
        .collect()
}

/// Space-padded ASCII Identify string → trimmed `String` (non-printable
/// bytes become `_`).
pub fn trim_ascii(raw: &[u8]) -> String {
    let s: String = raw
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '_'
            }
        })
        .collect();
    String::from(s.trim())
}

/// `ssss:bb:dd.f`, as Linux prints a PCI address.
pub fn bdf_string(a: narf_bus::PcieAddr) -> String {
    format!(
        "{:04x}:{:02x}:{:02x}.{}",
        a.segment, a.bus, a.device, a.function
    )
}

/// Controller name for probe-order `instance`.
pub fn controller_name(instance: u32) -> String {
    format!("nvme{instance}")
}

/// Block name of the controller's `index`-th registered namespace (0-based).
pub fn namespace_name(instance: u32, index: usize) -> String {
    format!("nvme{instance}n{}", index + 1)
}

/// Controller-level identity inputs.
#[derive(Clone, Debug, Default)]
pub struct ControllerIdentity {
    pub instance: u32,
    pub bus_path: String,
    pub vendor_id: u16,
    pub model: String,
    pub serial: String,
    pub firmware: String,
}

/// The [`DiskIdentity`] of one namespace.
pub fn disk_identity(ctrl: &ControllerIdentity, ns: &NamespaceInfo) -> DiskIdentity {
    DiskIdentity {
        transport: "nvme",
        bus_path: ctrl.bus_path.clone(),
        controller: controller_name(ctrl.instance),
        model: ctrl.model.clone(),
        serial: ctrl.serial.clone(),
        firmware: ctrl.firmware.clone(),
        vendor_id: ctrl.vendor_id,
        nsid: ns.nsid,
        eui64: ns.ids.eui64,
        nguid: ns.ids.nguid,
        uuid: ns.ids.uuid,
    }
}

/// Register every namespace of one controller with the block registry
/// (each wrapped in the `narf.disks` guard by the registry) and scan each
/// for partitions. `make_dev(nsid)` builds the namespace's block device.
/// Returns the registered namespace names, in order.
///
/// Partition-scan failures are not fatal: an unpartitioned namespace keeps
/// its whole-disk entry.
pub fn register_namespaces(
    ctrl: &ControllerIdentity,
    namespaces: &[NamespaceInfo],
    mut make_dev: impl FnMut(u32) -> Arc<dyn BlockDeviceSync>,
) -> Vec<&'static str> {
    use core::fmt::Write as _;
    let mut names = Vec::new();
    for (index, ns) in namespaces.iter().enumerate() {
        let name: &'static str =
            alloc::boxed::Box::leak(namespace_name(ctrl.instance, index).into_boxed_str());
        let identity = disk_identity(ctrl, ns);
        let _ = writeln!(
            narf_console::Writer,
            "nvme: {} ({}, {} {}): {} nsid {}, {} x {} B blocks, wwid {}",
            controller_name(ctrl.instance),
            ctrl.bus_path,
            ctrl.model,
            ctrl.serial,
            name,
            ns.nsid,
            ns.nsze,
            ns.lba_bytes,
            identity.wwid()
        );
        let dev = make_dev(ns.nsid);
        narf_block::register_block_device_with_identity(name, dev.clone(), identity);
        let _ = narf_block::partition::scan_and_register_partitions(dev, name);
        names.push(name);
    }
    names
}
